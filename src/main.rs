use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::oneshot,
    task::JoinHandle,
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
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    backend_addr: SocketAddr,

    /// Address to listen on for incoming TLS connections (e.g., 0.0.0.0:8443).
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8443")]
    listen_addr: SocketAddr,
}

struct TlsProxy {
    keypair: Keypair,
    listen_addr: SocketAddr,
    backend_addr: SocketAddr,
}

impl TlsProxy {
    fn new(keypair: Keypair, listen_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            keypair,
            listen_addr,
            backend_addr,
        }
    }

    /// Start the proxy in a background task
    fn start(&self, mut shutdown_rx: oneshot::Receiver<()>) -> JoinHandle<Result<()>> {
        let keypair = self.keypair.clone();
        let listen_addr = self.listen_addr;
        let backend_addr = self.backend_addr;

        tokio::spawn(async move {
            // Create rustls server config from keypair
            let tls_config = Arc::new(keypair.to_rpk_rustls_server_config());
            let tls_acceptor = TlsAcceptor::from(tls_config);

            // Set up the TCP listener
            let listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind to listen address: {}", listen_addr))?;

            info!("TLS proxy listening on {}", listen_addr);
            info!("Forwarding decrypted traffic to {}", backend_addr);
            info!("Using public key: {}", keypair.public_key());

            // Accept connections in a loop
            loop {
                tokio::select! {
                    // Accept a new connection
                    accepted = listener.accept() => {
                        let (client_stream, client_addr) = match accepted {
                            Ok(conn) => conn,
                            Err(e) => {
                                error!("Failed to accept incoming connection: {}", e);
                                continue; // Continue loop on accept error
                            }
                        };

                        let acceptor = tls_acceptor.clone();
                        let backend_addr = backend_addr; // Clone for the spawned task

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
                                    error!(
                                        "Failed to connect to backend {} for {}: {}",
                                        backend_addr, client_addr, e
                                    );
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
                                    Ok(bytes) => info!(
                                        "Client {} -> Backend {}: Copied {} bytes",
                                        client_addr, backend_addr, bytes
                                    ),
                                    Err(e) => error!(
                                        "Error copying Client -> Backend for {}: {}",
                                        client_addr, e
                                    ),
                                }
                                // Shut down the backend writer to signal EOF
                                let _ = backend_writer.shutdown().await;
                            };

                            // Forward data from backend to client
                            let backend_to_client = async {
                                match io::copy(&mut backend_reader, &mut tls_writer).await {
                                    Ok(bytes) => info!(
                                        "Backend {} -> Client {}: Copied {} bytes",
                                        backend_addr, client_addr, bytes
                                    ),
                                    Err(e) => error!(
                                        "Error copying Backend -> Client for {}: {}",
                                        client_addr, e
                                    ),
                                }
                                // Shut down the TLS writer to signal EOF
                                let _ = tls_writer.shutdown().await;
                            };

                            // Run both tasks concurrently and wait for both to complete
                            tokio::join!(client_to_backend, backend_to_client);
                            info!("Connection closed for: {}", client_addr);
                        });
                    }

                    // Check for shutdown signal
                    _ = &mut shutdown_rx => {
                        info!("Shutdown signal received, stopping listener.");
                        break; // Exit the loop
                    }
                }
            }
            Ok(()) // Return Ok when loop finishes gracefully
        })
    }
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
    let secret_bytes = hex::decode(secret_hex.trim()).context("Failed to decode hex secret key")?;

    // Create keypair from the secret key bytes
    if secret_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Secret key must be exactly 32 bytes (64 hex chars)"
        ));
    }
    let mut secret_key_array = [0u8; 32];
    secret_key_array.copy_from_slice(&secret_bytes);
    let keypair = Keypair::from_secret_key(&secret_key_array);

    // Create the proxy and start it in the background
    let proxy = TlsProxy::new(keypair, args.listen_addr, args.backend_addr);
    // Create a channel for shutdown signal
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let proxy_handle = proxy.start(shutdown_rx); // Pass receiver to start

    // Wait for Ctrl+C
    info!("Press Ctrl+C to stop the proxy");
    signal::ctrl_c().await.context("Failed to listen for Ctrl+C")?;
    info!("Received shutdown signal, shutting down...");

    // Send shutdown signal
    if shutdown_tx.send(()).is_err() {
        error!("Failed to send shutdown signal to proxy task.");
    }

    // Wait for the proxy task to complete
    match proxy_handle.await {
        Ok(Ok(())) => info!("Proxy task shut down gracefully."),
        Ok(Err(e)) => error!("Proxy task exited with error: {}", e),
        Err(e) => error!("Failed to join proxy task: {}", e),
    }

    info!("Shutdown complete.");

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use std::str::FromStr;

//     use super::*;

//     #[test]
//     fn test_main() {
//         let args = Args {
//             secret_file: PathBuf::from("secret"),
//             backend_addr: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
//             listen_addr: SocketAddr::from_str("0.0.0.0:8443").unwrap(),
//         };
//         main(args).unwrap();
//     }
// }