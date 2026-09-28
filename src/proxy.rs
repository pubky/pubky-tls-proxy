//! The proxy: accepts connections on all listen addresses and routes each one by its traffic kind.
//!
//! | Incoming traffic | Handling                                     | Backend              |
//! |------------------|----------------------------------------------|----------------------|
//! | Plain HTTP       | forwarded as is, or rejected if disabled    | `http_backend_addr`  |
//! | Pubky TLS        | TLS terminated with the pkarr keypair        | `http_backend_addr`  |
//! | Regular HTTPS    | forwarded as is, the backend terminates TLS  | `https_backend_addr` |

use crate::{
    forwarding::{self, Backend, ConnectionAddrs},
    prefixed_stream::PrefixedStream,
    traffic_detection::{detect_traffic, IncomingTraffic},
};
use anyhow::{Context, Result};
use pkarr::{Keypair, PublicKey};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// How long a client may take to send enough bytes to classify its traffic.
const TRAFFIC_DETECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything needed to start a [`Proxy`].
pub struct ProxyConfig {
    /// Keypair whose public key Pubky TLS clients connect to.
    pub keypair: Keypair,
    pub listen_addrs: Vec<SocketAddr>,
    /// Receives plain HTTP and decrypted Pubky TLS traffic.
    pub http_backend_addr: SocketAddr,
    /// Receives regular HTTPS traffic. Without it, regular HTTPS connections are closed.
    pub https_backend_addr: Option<SocketAddr>,
    /// Whether incoming plain HTTP is forwarded to the HTTP backend.
    pub plain_http: bool,
    /// Whether backend connections start with a PROXY protocol v1 header.
    pub send_proxy_protocol: bool,
}

/// Where each kind of traffic goes. Shared by all connections.
struct Routes {
    pubky_tls_acceptor: TlsAcceptor,
    http_backend: Backend,
    https_backend: Option<Backend>,
    plain_http: bool,
}

/// A running proxy. Listens until [`Proxy::shutdown`] is called.
pub struct Proxy {
    public_key: PublicKey,
    listen_addrs: Vec<SocketAddr>,
    listener_tasks: Vec<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
}

impl Proxy {
    /// Binds all listen addresses and starts accepting connections in background tasks.
    ///
    /// # Errors
    ///
    /// Fails if any listen address can't be bound. In that case nothing keeps running.
    pub async fn start(config: ProxyConfig) -> Result<Self> {
        let mut listeners = Vec::with_capacity(config.listen_addrs.len());
        for listen_addr in &config.listen_addrs {
            let listener = TcpListener::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind to listen address {listen_addr}"))?;
            listeners.push(listener);
        }

        // Report the actually bound addresses, which differ from the configured ones for port 0.
        let listen_addrs = listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect::<std::io::Result<Vec<_>>>()?;

        let routes = Arc::new(Routes {
            pubky_tls_acceptor: TlsAcceptor::from(Arc::new(
                config.keypair.to_rpk_rustls_server_config(),
            )),
            http_backend: Backend {
                addr: config.http_backend_addr,
                send_proxy_protocol: config.send_proxy_protocol,
            },
            https_backend: config.https_backend_addr.map(|addr| Backend {
                addr,
                send_proxy_protocol: config.send_proxy_protocol,
            }),
            plain_http: config.plain_http,
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener_tasks = listeners
            .into_iter()
            .map(|listener| {
                tokio::spawn(accept_connections(
                    listener,
                    routes.clone(),
                    shutdown_rx.clone(),
                ))
            })
            .collect();

        Ok(Self {
            public_key: config.keypair.public_key(),
            listen_addrs,
            listener_tasks,
            shutdown_tx,
        })
    }

    /// Stops accepting new connections. Connections already in progress are not interrupted.
    ///
    /// # Errors
    ///
    /// Fails if the listeners don't stop within `timeout` (default 10 seconds).
    pub async fn shutdown(self, timeout: Option<Duration>) -> Result<()> {
        // Sending only fails if all listeners are already gone, which is fine.
        let _ = self.shutdown_tx.send(true);

        let timeout = timeout.unwrap_or(Duration::from_secs(10));
        let all_listeners_stopped = wait_for_listeners_to_stop(self.listener_tasks);
        tokio::time::timeout(timeout, all_listeners_stopped)
            .await
            .with_context(|| format!("Proxy shutdown timed out after {timeout:?}"))
    }

    /// Addresses the proxy is listening on.
    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listen_addrs
    }

    /// Public key Pubky TLS clients connect to.
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

async fn wait_for_listeners_to_stop(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        if let Err(join_error) = task.await {
            error!("Listener task failed: {join_error}");
        }
    }
}

/// Accepts connections on `listener` and handles each in its own task, until shutdown.
async fn accept_connections(
    listener: TcpListener,
    routes: Arc<Routes>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, client_addr) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        error!("Failed to accept incoming connection: {error}");
                        continue;
                    }
                };
                debug!("Accepted connection from {client_addr}");

                let routes = routes.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(client, client_addr, &routes).await {
                        warn!("Connection from {client_addr} failed: {error:#}");
                    }
                });
            }

            // Also stops when the sender is dropped.
            _ = shutdown_rx.changed() => break,
        }
    }
}

/// Detects the kind of traffic on `client` and forwards it to the matching backend.
async fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    routes: &Routes,
) -> Result<()> {
    let addrs = ConnectionAddrs {
        client_addr,
        proxy_addr: client.local_addr()?,
    };

    // Clients that leave or stay silent before we know what they speak are mostly port
    // scanners. That's not worth a warning.
    let detected =
        match tokio::time::timeout(TRAFFIC_DETECTION_TIMEOUT, detect_traffic(&mut client)).await {
            Ok(Ok(detected)) => detected,
            Ok(Err(error)) if forwarding::is_hang_up(&error) => {
                debug!("{client_addr} closed the connection before sending a request");
                return Ok(());
            }
            Ok(Err(error)) => return Err(error).context("Failed to detect traffic kind"),
            Err(_elapsed) => {
                debug!("{client_addr} sent nothing within {TRAFFIC_DETECTION_TIMEOUT:?}, closing");
                return Ok(());
            }
        };

    // Replay the bytes consumed by detection so the next hop sees the whole connection.
    let client = PrefixedStream::new(detected.initial_bytes, client);

    match detected.traffic {
        IncomingTraffic::PlainHttp => {
            if !routes.plain_http {
                debug!("{client_addr}: plain HTTP rejected");
                return Ok(());
            }
            info!("{client_addr}: plain HTTP -> {}", routes.http_backend.addr);
            forwarding::forward_plain_http(client, routes.http_backend, addrs).await
        }
        IncomingTraffic::PubkyTls => {
            info!("{client_addr}: Pubky TLS -> {}", routes.http_backend.addr);
            forwarding::forward_pubky_tls(
                client,
                &routes.pubky_tls_acceptor,
                routes.http_backend,
                addrs,
            )
            .await
        }
        IncomingTraffic::RegularTls => {
            let Some(https_backend) = routes.https_backend else {
                debug!("{client_addr}: regular HTTPS rejected, no HTTPS backend configured");
                return Ok(());
            };
            info!("{client_addr}: regular HTTPS -> {}", https_backend.addr);
            forwarding::forward_regular_tls(client, https_backend, addrs).await
        }
    }
}

#[cfg(test)]
mod tests;
