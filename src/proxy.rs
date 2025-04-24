use anyhow::{Context, Result};
use pkarr::Keypair;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

pub struct TlsProxy {
    keypair: Keypair,
    listen_addr: SocketAddr,
    backend_addr: SocketAddr,
}

impl TlsProxy {
    pub fn new(keypair: Keypair, listen_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        Self {
            keypair,
            listen_addr,
            backend_addr,
        }
    }

    /// Start the proxy in a background task
    pub fn start(&self, mut shutdown_rx: oneshot::Receiver<()>) -> JoinHandle<Result<()>> {
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


