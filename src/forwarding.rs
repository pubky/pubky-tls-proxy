//! Relays a classified client connection to its backend.

use crate::{proxy::ConnectionLimits, proxy_protocol};
use anyhow::{Context, Result};
use std::{
    io as std_io,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

const ERROR_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// A backend service that connections are forwarded to.
#[derive(Debug, Clone, Copy)]
pub struct Backend {
    pub addr: SocketAddr,
    /// Whether to start every backend connection with a PROXY protocol header.
    pub send_proxy_protocol: bool,
}

/// Addresses of the TCP connection between a client and this proxy.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionAddrs {
    pub client_addr: SocketAddr,
    pub proxy_addr: SocketAddr,
}

/// Forwards a plain HTTP connection to `backend`.
///
/// If the backend is unreachable, the client receives a `502 Bad Gateway` response.
pub async fn forward_plain_http(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    backend: Backend,
    addrs: ConnectionAddrs,
    limits: ConnectionLimits,
) -> Result<()> {
    let mut backend_stream =
        match connect_to_backend(backend, addrs, limits.backend_setup_timeout).await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = tokio::time::timeout(ERROR_RESPONSE_TIMEOUT, send_bad_gateway(&mut client))
                    .await;
                return Err(error);
            }
        };

    relay(&mut client, &mut backend_stream, limits.idle_timeout).await
}

/// Terminates raw public key TLS with `tls_acceptor` and forwards the decrypted HTTP to `backend`.
pub async fn forward_raw_public_key_tls(
    client: impl AsyncRead + AsyncWrite + Unpin,
    tls_acceptor: &TlsAcceptor,
    backend: Backend,
    addrs: ConnectionAddrs,
    limits: ConnectionLimits,
) -> Result<()> {
    let decrypted_client =
        match tokio::time::timeout(limits.rpk_handshake_timeout, tls_acceptor.accept(client)).await
        {
            Ok(result) => result.context("Raw public key TLS handshake failed")?,
            Err(_) => {
                debug!(
                    "Raw public key TLS handshake timed out for {}",
                    addrs.client_addr
                );
                return Ok(());
            }
        };
    debug!(
        "Raw public key TLS handshake successful for {}",
        addrs.client_addr
    );

    forward_plain_http(decrypted_client, backend, addrs, limits).await
}

/// Forwards a TLS passthrough connection to `backend` without decrypting it.
///
/// If the backend is unreachable the connection is simply closed. There is no way to
/// answer with an HTTP error, because only the backend can complete the TLS handshake.
pub async fn forward_tls_passthrough(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    backend: Backend,
    addrs: ConnectionAddrs,
    limits: ConnectionLimits,
) -> Result<()> {
    let mut backend_stream =
        connect_to_backend(backend, addrs, limits.backend_setup_timeout).await?;

    relay(&mut client, &mut backend_stream, limits.idle_timeout).await
}

/// Connects to `backend` and, if enabled, announces the client with a PROXY protocol header.
async fn connect_to_backend(
    backend: Backend,
    addrs: ConnectionAddrs,
    timeout: Duration,
) -> Result<TcpStream> {
    tokio::time::timeout(timeout, establish_backend_connection(backend, addrs))
        .await
        .with_context(|| format!("Backend setup timed out for {}", backend.addr))?
}

async fn establish_backend_connection(
    backend: Backend,
    addrs: ConnectionAddrs,
) -> Result<TcpStream> {
    let mut backend_stream = TcpStream::connect(backend.addr)
        .await
        .with_context(|| format!("Failed to connect to backend {}", backend.addr))?;

    if backend.send_proxy_protocol {
        let header = proxy_protocol::v1_header(addrs.client_addr, addrs.proxy_addr);
        backend_stream
            .write_all(header.as_bytes())
            .await
            .with_context(|| format!("Failed to send PROXY protocol header to {}", backend.addr))?;
    }

    Ok(backend_stream)
}

/// Best effort: the connection is closed afterwards either way.
/// Backend diagnostics stay in the error returned to the caller for server-side logging.
async fn send_bad_gateway(client: &mut (impl AsyncWrite + Unpin)) {
    let body = "Bad Gateway\n";
    let response = format!(
        "HTTP/1.1 502 Bad Gateway\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    if let Err(write_error) = client.write_all(response.as_bytes()).await {
        debug!("Failed to send 502 response to client: {write_error}");
    }
    let _ = client.shutdown().await;
}

/// Copies in both directions until both sides close or neither transfers data for `idle_timeout`.
async fn relay(
    client: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    idle_timeout: Duration,
) -> Result<()> {
    let (activity_tx, mut activity_rx) = watch::channel(());
    let mut client = ActivityStream::new(client, activity_tx.clone());
    let mut backend = ActivityStream::new(backend, activity_tx);
    let transfer = io::copy_bidirectional(&mut client, &mut backend);
    tokio::pin!(transfer);
    let result = loop {
        tokio::select! {
            biased;
            result = &mut transfer => break result,
            changed = activity_rx.changed() => {
                // A successful read or write starts another full idle interval.
                if changed.is_err() { break Err(io::Error::other("activity tracker stopped")); }
            }
            _ = tokio::time::sleep(idle_timeout) => {
                debug!("Connection idle for {idle_timeout:?}, closing");
                return Ok(());
            }
        }
    };
    match result {
        Ok((client_to_backend_bytes, backend_to_client_bytes)) => {
            debug!("Relayed {client_to_backend_bytes} bytes to backend and {backend_to_client_bytes} bytes to client");
            Ok(())
        }
        Err(error) if is_hang_up(&error) => {
            debug!("Peer closed the connection: {error}");
            Ok(())
        }
        Err(error) => Err(error).context("Error while relaying data"),
    }
}

/// Reports data transfer in either direction without changing relay backpressure or half-closes.
struct ActivityStream<S> {
    inner: S,
    activity: watch::Sender<()>,
}

impl<S> ActivityStream<S> {
    fn new(inner: S, activity: watch::Sender<()>) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std_io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.send_replace(());
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std_io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(bytes)) if bytes > 0) {
            self.activity.send_replace(());
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std_io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std_io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Whether `error` means the other side hung up, rather than a failure worth reporting.
///
/// Clients (and internet scanners) regularly drop connections: resets, broken pipes,
/// sockets that are already gone. Many TLS clients also close the TCP connection without
/// sending close_notify, which rustls reports as `UnexpectedEof`.
pub fn is_hang_up(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn inactive_relay_closes_both_sides() {
        let (mut client, mut proxy_client) = io::duplex(64);
        let (mut backend, mut proxy_backend) = io::duplex(64);
        let relay_task = tokio::spawn(async move {
            relay(
                &mut proxy_client,
                &mut proxy_backend,
                Duration::from_millis(100),
            )
            .await
        });

        let result = tokio::time::timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap();
        result.unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn active_relay_survives_idle_interval_and_preserves_half_close() {
        let (mut client, mut proxy_client) = io::duplex(64);
        let (mut backend, mut proxy_backend) = io::duplex(64);
        let relay_task = tokio::spawn(async move {
            relay(
                &mut proxy_client,
                &mut proxy_backend,
                Duration::from_millis(150),
            )
            .await
        });

        for _ in 0..4 {
            client.write_all(b"x").await.unwrap();
            let mut byte = [0];
            backend.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        client.shutdown().await.unwrap();
        let mut end = [0];
        assert_eq!(backend.read(&mut end).await.unwrap(), 0);
        backend.write_all(b"reply").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"reply");
        tokio::time::timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn peer_disconnects_are_hang_ups() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
        ] {
            assert!(is_hang_up(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn other_io_errors_are_not_hang_ups() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Other,
        ] {
            assert!(!is_hang_up(&io::Error::from(kind)), "{kind:?}");
        }
    }
}
