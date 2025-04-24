use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, Level};
use tracing_subscriber;

/// A TLS terminating proxy using a pkarr secret key.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the file containing the pkarr secret key in HEX format.
    #[arg(long, value_name = "FILE")]
    secret_file: PathBuf,

    /// Address to proxy requests to (e.g., 127.0.0.1:8080).
    #[arg(long, value_name = "ADDR")]
    backend_addr: SocketAddr,

    /// Address to listen on for incoming TLS connections (e.g., 0.0.0.0:8443).
    #[arg(long, value_name = "ADDR")]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Parse command line arguments
    let args = Args::parse();

    // Load secret key from file
    info!("Loading secret key from {:?}", args.secret_file);
    let secret_hex = fs::read_to_string(&args.secret_file)
        .with_context(|| format!("Failed to read secret file: {:?}", args.secret_file))?;
    
    // Convert hex to bytes
    let secret_bytes = hex::decode(secret_hex.trim())
        .context("Failed to decode hex secret key")?;
    
    // Create keypair from the secret key bytes
    if secret_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Secret key must be exactly 32 bytes (64 hex chars)"));
    }
    
    // Use the pkarr library's from_secret_key method to create a Keypair
    // The secret key in pkarr is a 32-byte array
    let mut secret_key_array = [0u8; 32];
    secret_key_array.copy_from_slice(&secret_bytes);
    
    // Create a pkarr Keypair from the secret key
    let keypair = Keypair::from_secret_key(&secret_key_array);
    
    // Get the public key (useful for logging)
    let public_key = keypair.public_key();
    info!("Using public key: {}", public_key);
    
    // Create rustls server config from keypair
    // This uses the pkarr method that generates a self-signed certificate
    // using the Raw Public Key (RPK) format according to RFC 7250
    let tls_config = Arc::new(keypair.to_rpk_rustls_server_config());
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Set up the TCP listener
    let listener = TcpListener::bind(args.listen_addr)
        .await
        .with_context(|| format!("Failed to bind to listen address: {}", args.listen_addr))?;
    
    info!("TLS proxy listening on {}", args.listen_addr);
    info!("Forwarding decrypted traffic to {}", args.backend_addr);

    // Accept connections in a loop
    loop {
        let (client_stream, client_addr) = listener.accept().await
            .context("Failed to accept incoming connection")?;

        let acceptor = tls_acceptor.clone();
        let backend_addr = args.backend_addr;

        // Spawn a new task for each connection
        tokio::spawn(async move {
            info!("Accepted connection from: {}", client_addr);

            // Perform TLS handshake
            let tls_stream = match acceptor.accept(client_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("TLS handshake failed for {}: {}", client_addr, e);
                    return;
                }
            };
            info!("TLS handshake successful for: {}", client_addr);

            // Connect to backend server
            let backend_stream = match TcpStream::connect(backend_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Failed to connect to backend {} for {}: {}", backend_addr, client_addr, e);
                    return;
                }
            };
            info!("Connected to backend {} for: {}", backend_addr, client_addr);

            // Split streams for bidirectional copying
            let (mut tls_reader, mut tls_writer) = io::split(tls_stream);
            let (mut backend_reader, mut backend_writer) = io::split(backend_stream);

            // Forward data from client to backend
            let client_to_backend = async {
                match io::copy(&mut tls_reader, &mut backend_writer).await {
                    Ok(bytes) => info!("Client {} -> Backend {}: Copied {} bytes", client_addr, backend_addr, bytes),
                    Err(e) => error!("Error copying Client -> Backend for {}: {}", client_addr, e),
                }
                // Shut down the backend writer to signal EOF
                let _ = backend_writer.shutdown().await;
            };

            // Forward data from backend to client
            let backend_to_client = async {
                match io::copy(&mut backend_reader, &mut tls_writer).await {
                    Ok(bytes) => info!("Backend {} -> Client {}: Copied {} bytes", backend_addr, client_addr, bytes),
                    Err(e) => error!("Error copying Backend -> Client for {}: {}", client_addr, e),
                }
                // Shut down the TLS writer to signal EOF
                let _ = tls_writer.shutdown().await;
            };

            // Run both tasks concurrently and wait for both to complete
            tokio::join!(client_to_backend, backend_to_client);
            info!("Connection closed for: {}", client_addr);
        });
    }
}



