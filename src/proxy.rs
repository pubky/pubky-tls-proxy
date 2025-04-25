use anyhow::{Context, Result};
use pkarr::{Keypair, PublicKey};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
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
    join_handle: JoinHandle<Result<()>>,
    shutdown_tx: oneshot::Sender<()>,
}

impl TlsProxy {
    pub fn run(keypair: Keypair, listen_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        let (join_handle, shutdown_tx) = Self::start(keypair.clone(), listen_addr.clone(), backend_addr.clone());
        Self {
            keypair,
            listen_addr,
            backend_addr,
            join_handle,
            shutdown_tx,
        }
    }

    /// Shutdown the proxy.
    pub async fn shutdown(self, timeout: Option<Duration>) -> anyhow::Result<()> {
        if let Err(_) = self.shutdown_tx.send(()) {
            anyhow::bail!("Failed to send shutdown signal");
        };
        let timeout_duration = timeout.unwrap_or(Duration::from_secs(10));
        match tokio::time::timeout(timeout_duration, self.join_handle).await {
            Ok(result) => result?,
            Err(_) => {
                // Timeout occurred
                anyhow::bail!("Proxy shutdown timed out after {:?}", timeout_duration)
            }
        }
    }

    /// Start the proxy in a background task
    fn start(keypair: Keypair, listen_addr: SocketAddr, backend_addr: SocketAddr) -> (JoinHandle<Result<()>>, oneshot::Sender<()>) {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
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
        });

        (handle, shutdown_tx)
    }

    /// Backend address the traffic is forwarded to.
    pub fn backend_addr(&self) -> SocketAddr {
        self.backend_addr
    }

    /// Address the proxy is listening on.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Public key of the proxy.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
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
                                // Read the request
                                let mut buffer = vec![0; 4096];
                                let n = match stream.read(&mut buffer).await {
                                    Ok(n) => n,
                                    Err(e) => {
                                        error!("[Backend] Error reading request: {}", e);
                                        return;
                                    }
                                };
                                
                                if n == 0 {
                                    // Empty request
                                    error!("[Backend] Empty request from {}", client_addr);
                                    return;
                                }
                                
                                // Extract the request body
                                let req_data = String::from_utf8_lossy(&buffer[0..n]);
                                
                                // For HTTP POST request, find the request body after headers
                                let body = if req_data.contains("POST") {
                                    if let Some(idx) = req_data.find("\r\n\r\n") {
                                        let body_start = idx + 4;
                                        if body_start < req_data.len() {
                                            &req_data[body_start..]
                                        } else {
                                            ""
                                        }
                                    } else {
                                        ""
                                    }
                                } else {
                                    ""
                                };
                                
                                info!("[Backend] Received request: {} bytes", n);
                                
                                // Send HTTP response with the same body
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                    Content-Type: text/plain\r\n\
                                    Content-Length: {}\r\n\
                                    Connection: close\r\n\
                                    \r\n\
                                    {}",
                                    body.len(),
                                    body
                                );
                                
                                if let Err(e) = stream.write_all(response.as_bytes()).await {
                                    error!("[Backend] Error writing response: {}", e);
                                    return;
                                }
                                
                                if let Err(e) = stream.flush().await {
                                    error!("[Backend] Error flushing: {}", e);
                                    return;
                                }
                                
                                info!("[Backend] Echoed {} bytes for {}", body.len(), client_addr);
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

        let proxy = TlsProxy::run(keypair.clone(), proxy_addr, backend_addr);

        // Publish pkarr record
        let pkarr_client = pkarr::Client::builder().build()?;
        let root_name = Name::new(".").unwrap();

        // Add A record
        let mut builder = pkarr::SignedPacket::builder();
        builder = builder.a(root_name.clone(), "127.0.0.1".parse().unwrap(), 300);

        // Add SVCB record
        let mut svcb = SVCB::new(0, root_name.clone());
        svcb.set_port(proxy_addr.port() as u16);
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
        proxy.shutdown(Some(Duration::from_secs(5))).await?;
        let _ = backend_shutdown_tx.send(());
        let _ = backend_handle.await;

        Ok(())
    }
}
