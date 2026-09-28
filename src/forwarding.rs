//! Relays a classified client connection to its backend.

use crate::proxy_protocol;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

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
) -> Result<()> {
    let mut backend_stream = match connect_to_backend(backend, addrs).await {
        Ok(stream) => stream,
        Err(error) => {
            send_bad_gateway(&mut client, &error).await;
            return Err(error);
        }
    };

    relay(&mut client, &mut backend_stream).await
}

/// Terminates Pubky TLS with `tls_acceptor` and forwards the decrypted HTTP to `backend`.
pub async fn forward_pubky_tls(
    client: impl AsyncRead + AsyncWrite + Unpin,
    tls_acceptor: &TlsAcceptor,
    backend: Backend,
    addrs: ConnectionAddrs,
) -> Result<()> {
    let decrypted_client = tls_acceptor
        .accept(client)
        .await
        .context("Pubky TLS handshake failed")?;
    debug!("Pubky TLS handshake successful for {}", addrs.client_addr);

    forward_plain_http(decrypted_client, backend, addrs).await
}

/// Forwards a regular TLS connection to `backend` without decrypting it.
///
/// If the backend is unreachable the connection is simply closed. There is no way to
/// answer with an HTTP error, because only the backend can complete the TLS handshake.
pub async fn forward_regular_tls(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    backend: Backend,
    addrs: ConnectionAddrs,
) -> Result<()> {
    let mut backend_stream = connect_to_backend(backend, addrs).await?;

    relay(&mut client, &mut backend_stream).await
}

/// Connects to `backend` and, if enabled, announces the client with a PROXY protocol header.
async fn connect_to_backend(backend: Backend, addrs: ConnectionAddrs) -> Result<TcpStream> {
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
async fn send_bad_gateway(client: &mut (impl AsyncWrite + Unpin), error: &anyhow::Error) {
    let body = format!("Backend connection error: {error:#}");
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

/// Copies data in both directions until both sides have closed their connection.
async fn relay(
    client: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<()> {
    match io::copy_bidirectional(client, backend).await {
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
