//! The proxy: accepts connections on all listen addresses and routes each one by its traffic kind.
//!
//! | Incoming traffic        | Handling                                    | Backend                        |
//! |-------------------------|---------------------------------------------|--------------------------------|
//! | Plain HTTP              | forwarded as is, or rejected if disabled     | `http_backend_addr`            |
//! | Raw public key TLS      | TLS terminated with the proxy's keypair      | `http_backend_addr`            |
//! | Certificate-based HTTPS | forwarded as is, the backend terminates TLS  | `tls_passthrough_backend_addr` |
//!
//! Unparseable TLS handshakes also use the TLS passthrough backend.

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
    sync::{watch, Semaphore},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// How long a client may take to send enough bytes to classify its traffic.
const TRAFFIC_DETECTION_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Resource limits shared by all listeners of a proxy.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    pub max_connections: usize,
    pub rpk_handshake_timeout: Duration,
    pub backend_setup_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            rpk_handshake_timeout: Duration::from_secs(10),
            backend_setup_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Everything needed to start a [`Proxy`].
pub struct ProxyConfig {
    /// Keypair used for raw public key TLS.
    pub keypair: Keypair,
    pub listen_addrs: Vec<SocketAddr>,
    /// Receives plain HTTP and decrypted raw public key TLS traffic.
    pub http_backend_addr: SocketAddr,
    /// Receives TLS passthrough traffic. Without it, those connections are closed.
    pub tls_passthrough_backend_addr: Option<SocketAddr>,
    /// Whether incoming plain HTTP is forwarded to the HTTP backend.
    pub plain_http: bool,
    /// Whether backend connections start with a PROXY protocol v1 header.
    pub send_proxy_protocol: bool,
    pub limits: ConnectionLimits,
}

/// Where each kind of traffic goes. Shared by all connections.
struct Routes {
    raw_public_key_tls_acceptor: TlsAcceptor,
    http_backend: Backend,
    tls_passthrough_backend: Option<Backend>,
    plain_http: bool,
}

/// A running proxy. Listens until [`Proxy::shutdown`] is called.
pub struct Proxy {
    public_key: PublicKey,
    listen_addrs: Vec<SocketAddr>,
    listener_tasks: JoinSet<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl Proxy {
    /// Binds all listen addresses and starts accepting connections in background tasks.
    ///
    /// # Errors
    ///
    /// Fails if any listen address can't be bound. In that case nothing keeps running.
    pub async fn start(config: ProxyConfig) -> Result<Self> {
        anyhow::ensure!(
            config.limits.max_connections > 0
                && config.limits.max_connections <= Semaphore::MAX_PERMITS,
            "max_connections must be between 1 and {}",
            Semaphore::MAX_PERMITS
        );
        anyhow::ensure!(
            !config.limits.rpk_handshake_timeout.is_zero(),
            "rpk_handshake_timeout must be positive"
        );
        anyhow::ensure!(
            !config.limits.backend_setup_timeout.is_zero(),
            "backend_setup_timeout must be positive"
        );
        anyhow::ensure!(
            !config.limits.idle_timeout.is_zero(),
            "idle_timeout must be positive"
        );
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
            raw_public_key_tls_acceptor: TlsAcceptor::from(Arc::new(
                config.keypair.to_rpk_rustls_server_config(),
            )),
            http_backend: Backend {
                addr: config.http_backend_addr,
                send_proxy_protocol: config.send_proxy_protocol,
            },
            tls_passthrough_backend: config.tls_passthrough_backend_addr.map(|addr| Backend {
                addr,
                send_proxy_protocol: config.send_proxy_protocol,
            }),
            plain_http: config.plain_http,
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let connection_slots = Arc::new(Semaphore::new(config.limits.max_connections));
        let mut listener_tasks = JoinSet::new();
        for listener in listeners {
            listener_tasks.spawn(accept_connections(
                listener,
                routes.clone(),
                connection_slots.clone(),
                config.limits,
                shutdown_rx.clone(),
            ));
        }

        Ok(Self {
            public_key: config.keypair.public_key(),
            listen_addrs,
            listener_tasks,
            shutdown_tx,
        })
    }

    /// Stops accepting new connections and waits for active connections to finish.
    /// Connections still running at the deadline are cancelled.
    ///
    /// # Errors
    ///
    /// Fails if draining exceeds `timeout` (default 10 seconds), or a listener task fails.
    pub async fn shutdown(mut self, timeout: Option<Duration>) -> Result<()> {
        // Sending only fails if all listeners are already gone, which is fine.
        let _ = self.shutdown_tx.send(true);

        let timeout = timeout.unwrap_or(Duration::from_secs(10));
        let result = tokio::time::timeout(
            timeout,
            wait_for_listeners_to_stop(&mut self.listener_tasks),
        )
        .await
        .with_context(|| format!("Proxy shutdown timed out after {timeout:?}"))
        .and_then(|result| result);
        if result.is_err() {
            // Cancelling each listener also drops its task set, cancelling its connections.
            self.listener_tasks.shutdown().await;
        }
        result
    }

    /// Addresses the proxy is listening on.
    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listen_addrs
    }

    /// Public key used for raw public key TLS and naming the Public Key Domain.
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

async fn wait_for_listeners_to_stop(tasks: &mut JoinSet<()>) -> Result<()> {
    while let Some(result) = tasks.join_next().await {
        result.context("Listener task failed")?;
    }
    Ok(())
}

/// Accepts connections on `listener` and handles each in its own task, until shutdown.
async fn accept_connections(
    listener: TcpListener,
    routes: Arc<Routes>,
    connection_slots: Arc<Semaphore>,
    limits: ConnectionLimits,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            // Check shutdown before accepting another connection, even under continuous load.
            _ = shutdown_rx.changed() => break,

            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    error!("Connection task failed: {error}");
                }
            }

            accepted = listener.accept() => {
                let (client, client_addr) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        error!("Failed to accept incoming connection: {error}");
                        tokio::select! {
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                            _ = shutdown_rx.changed() => break,
                        }
                        continue;
                    }
                };
                debug!("Accepted connection from {client_addr}");

                // Reject overload before spawning: waiting tasks would themselves consume resources.
                let Ok(slot) = connection_slots.clone().try_acquire_owned() else {
                    debug!("Connection limit reached, closing {client_addr}");
                    continue;
                };

                let routes = routes.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    if let Err(error) = handle_connection(client, client_addr, &routes, limits).await {
                        warn!("Connection from {client_addr} failed: {error:#}");
                    }
                });
            }
        }
    }

    // Close the listening socket before draining, so new clients cannot queue behind it.
    drop(listener);
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            error!("Connection task failed: {error}");
        }
    }
}

/// Detects the kind of traffic on `client` and forwards it to the matching backend.
async fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    routes: &Routes,
    limits: ConnectionLimits,
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
            forwarding::forward_plain_http(client, routes.http_backend, addrs, limits).await
        }
        IncomingTraffic::RawPublicKeyTls => {
            info!(
                "{client_addr}: raw public key TLS -> {}",
                routes.http_backend.addr
            );
            forwarding::forward_raw_public_key_tls(
                client,
                &routes.raw_public_key_tls_acceptor,
                routes.http_backend,
                addrs,
                limits,
            )
            .await
        }
        IncomingTraffic::TlsPassthrough => {
            let Some(backend) = routes.tls_passthrough_backend else {
                debug!("{client_addr}: TLS passthrough rejected, no TLS passthrough backend configured");
                return Ok(());
            };
            info!("{client_addr}: TLS passthrough -> {}", backend.addr);
            forwarding::forward_tls_passthrough(client, backend, addrs, limits).await
        }
    }
}

#[cfg(test)]
mod tests;
