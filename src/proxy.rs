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

#[cfg(test)]
mod tests {
    use pkarr::dns::{rdata::SVCB, Name};
    use tracing::Level;
    use tracing_subscriber;

    use super::*;

    async fn run_backend_server(addr: SocketAddr, mut shutdown_rx: tokio::sync::oneshot::Receiver<()>) {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind backend server");
        info!("[Backend] Listening on {}", addr);

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((mut stream, client_addr)) => {
                            info!("[Backend] Accepted connection from {}", client_addr);
                            tokio::spawn(async move {
                                let (mut reader, mut writer) = stream.split();
                                match io::copy(&mut reader, &mut writer).await {
                                    Ok(bytes) => info!("[Backend] Echoed {} bytes for {}", bytes, client_addr),
                                    Err(e) => error!("[Backend] Error echoing data for {}: {}", client_addr, e),
                                }
                            });
                        }
                        Err(e) => {
                            error!("[Backend] Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("[Backend] Shutdown signal received.");
                    break;
                }
            }
        }
    }

    #[tokio::test]
    async fn test_proxy_request() -> Result<()> {
        // Setup simple tracing for test output
        tracing_subscriber::fmt().with_max_level(Level::INFO).init();
        
        let keypair = Keypair::random();

        // Start the backend server
        let backend_addr: SocketAddr = format!("127.0.0.1:5000").parse()?;
        let (backend_shutdown_tx, backend_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let backend_handle = tokio::spawn(run_backend_server(backend_addr, backend_shutdown_rx));


        // Create and start the proxy
        let proxy_addr: SocketAddr = format!("127.0.0.1:5001").parse()?;

        let proxy = TlsProxy::new(keypair.clone(), proxy_addr, backend_addr);
        let (proxy_shutdown_tx, proxy_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let proxy_handle = proxy.start(proxy_shutdown_rx);

        // Publish pkarr record
        let pkarr_client = pkarr::Client::builder().build()?;
        let root_name = Name::new(".").unwrap();

        // Add A record
        let mut builder = pkarr::SignedPacket::builder();
        builder = builder.a(root_name.clone(), "127.0.0.1".parse().unwrap(), 300);

        // Add SVCB record
        let mut svcb = SVCB::new(0, root_name.clone());
        svcb.set_port(81);
        builder = builder.https(root_name.clone(), svcb, 60 * 60);

        let packet = builder.build(&keypair).unwrap();
        pkarr_client.publish(&packet, None).await?;

        // Configure Reqwest client to trust the proxy's RPK
        let client = reqwest::ClientBuilder::from(pkarr_client).build()?;

        let url = format!("https://{}:{}", keypair.public_key().to_z32(), proxy_addr.port());
        let request_body = "Hello from client!";

        info!("Making request to {}", url);
        // Make request to the proxy
        let response = client
            .post(&url)
            .body(request_body)
            .send()
            .await
            .context("Failed to send request via proxy")?;

        info!("Received response: {:?}", response);

        // Verify response
        assert!(response.status().is_success());
        let response_body = response
            .text()
            .await
            .context("Failed to read response body")?;
        assert_eq!(response_body, request_body);
        info!("Response verified successfully.");

        // Shutdown servers
        let _ = proxy_shutdown_tx.send(());
        let _ = backend_shutdown_tx.send(());

        // Wait for tasks to complete
        let _ = proxy_handle.await;
        let _ = backend_handle.await;

        Ok(())
    }
}
