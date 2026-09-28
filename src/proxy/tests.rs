//! End-to-end tests: real TCP connections through a running proxy to test backends.

use super::*;
use crate::test_support::{raw_public_key_client_hello, x509_client_hello};
use pkarr::dns::{rdata::SVCB, Name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn plain_http_is_forwarded_to_http_backend_with_proxy_header() -> Result<()> {
    let http_backend = start_http_echo_backend().await?;
    let proxy = start_proxy(http_backend, None, true).await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    let client_port = client.local_addr()?.port();
    let response = send_http_post(&mut client, "hello").await?;

    let expected_proxy_header = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {}",
        proxy.listen_addrs()[0].port()
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains(&format!("x-proxy-header: {expected_proxy_header}\r\n")),
        "{response}"
    );
    assert!(response.ends_with("\r\n\r\nhello"), "{response}");

    proxy.shutdown(None).await
}

#[tokio::test]
async fn no_proxy_header_is_sent_when_disabled() -> Result<()> {
    let http_backend = start_http_echo_backend().await?;
    let proxy = start_proxy(http_backend, None, false).await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    let response = send_http_post(&mut client, "hello").await?;

    assert!(response.contains("x-proxy-header: none\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\nhello"), "{response}");

    proxy.shutdown(None).await
}

#[tokio::test]
async fn every_listen_addr_accepts_connections() -> Result<()> {
    let http_backend = start_http_echo_backend().await?;
    let proxy = Proxy::start(ProxyConfig {
        listen_addrs: vec![localhost_any_port(), localhost_any_port()],
        ..proxy_config(http_backend, None, false)
    })
    .await?;

    for listen_addr in proxy.listen_addrs() {
        let mut client = TcpStream::connect(listen_addr).await?;
        let response = send_http_post(&mut client, "hello").await?;
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{listen_addr}: {response}"
        );
    }

    proxy.shutdown(None).await
}

#[tokio::test]
async fn plain_http_with_backend_down_gets_bad_gateway() -> Result<()> {
    let unreachable_backend = unused_localhost_addr();
    let proxy = start_proxy(unreachable_backend, None, true).await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    let response = send_http_post(&mut client, "hello").await?;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway"),
        "{response}"
    );
    assert!(response.contains("Backend connection error"), "{response}");

    proxy.shutdown(None).await
}

#[tokio::test]
async fn disabled_plain_http_is_closed_without_contacting_backend() -> Result<()> {
    let backend = TcpListener::bind(localhost_any_port()).await?;
    let proxy = Proxy::start(ProxyConfig {
        plain_http: false,
        ..proxy_config(backend.local_addr()?, None, true)
    })
    .await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;

    assert!(response.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backend.accept())
            .await
            .is_err()
    );

    proxy.shutdown(None).await
}

#[tokio::test]
async fn regular_https_is_passed_through_unchanged_to_https_backend() -> Result<()> {
    let http_backend = start_http_echo_backend().await?;
    let client_hello = x509_client_hello("example.com");
    let https_backend = RecordingBackend::start().await?;
    let proxy = Proxy::start(ProxyConfig {
        plain_http: false,
        ..proxy_config(http_backend, Some(https_backend.addr()?), true)
    })
    .await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    let client_port = client.local_addr()?.port();
    client.write_all(&client_hello).await?;

    let expected_proxy_header = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {}\r\n",
        proxy.listen_addrs()[0].port()
    );
    let mut expected_bytes = expected_proxy_header.into_bytes();
    expected_bytes.extend_from_slice(&client_hello);
    assert_eq!(
        https_backend.receive(expected_bytes.len()).await?,
        expected_bytes
    );

    proxy.shutdown(None).await
}

#[tokio::test]
async fn client_hanging_up_before_sending_anything_is_not_a_failure() -> Result<()> {
    let routes = Routes {
        pubky_tls_acceptor: TlsAcceptor::from(Arc::new(
            Keypair::random().to_rpk_rustls_server_config(),
        )),
        http_backend: Backend {
            addr: unused_localhost_addr(),
            send_proxy_protocol: true,
        },
        https_backend: None,
        plain_http: true,
    };
    let listener = TcpListener::bind(localhost_any_port()).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (proxy_side, client_addr) = listener.accept().await?;

    drop(client);
    let result = handle_connection(
        proxy_side,
        client_addr,
        &routes,
        ConnectionLimits::default(),
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn regular_https_without_https_backend_is_closed() -> Result<()> {
    let http_backend = start_http_echo_backend().await?;
    let proxy = start_proxy(http_backend, None, true).await?;

    let mut client = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    client.write_all(&x509_client_hello("example.com")).await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;

    assert!(response.is_empty());

    proxy.shutdown(None).await
}

#[tokio::test]
async fn stalled_pubky_handshake_releases_its_connection_slot() -> Result<()> {
    let backend = start_http_echo_backend().await?;
    let proxy = Proxy::start(ProxyConfig {
        limits: ConnectionLimits {
            max_connections: 1,
            handshake_timeout: Duration::from_millis(100),
            ..ConnectionLimits::default()
        },
        ..proxy_config(backend, None, false)
    })
    .await?;

    let mut stalled = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    stalled.write_all(&raw_public_key_client_hello()).await?;
    let mut bytes = [0u8; 4096];
    // rustls may respond with handshake data before waiting for the client's next flight.
    tokio::time::timeout(Duration::from_secs(2), async {
        while stalled.read(&mut bytes).await? != 0 {}
        anyhow::Ok(())
    })
    .await??;

    let mut next = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    let response = send_http_post(&mut next, "slot available").await?;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    proxy.shutdown(None).await
}

#[tokio::test]
async fn connection_limit_is_shared_across_listeners() -> Result<()> {
    let backend = start_http_echo_backend().await?;
    let proxy = Proxy::start(ProxyConfig {
        listen_addrs: vec![localhost_any_port(), localhost_any_port()],
        limits: ConnectionLimits {
            max_connections: 1,
            ..ConnectionLimits::default()
        },
        ..proxy_config(backend, None, false)
    })
    .await?;

    let mut held = TcpStream::connect(proxy.listen_addrs()[0]).await?;
    held.write_all(&raw_public_key_client_hello()).await?;
    // Receiving the server's handshake flight confirms the first listener owns the slot.
    let mut handshake = [0u8; 4096];
    assert!(tokio::time::timeout(Duration::from_secs(2), held.read(&mut handshake)).await?? > 0);
    let mut rejected = TcpStream::connect(proxy.listen_addrs()[1]).await?;
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut byte)).await??,
        0
    );

    drop(held);
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut available = TcpStream::connect(proxy.listen_addrs()[1]).await?;
            if let Ok(response) = send_http_post(&mut available, "available").await {
                break anyhow::Ok(response);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    proxy.shutdown(None).await
}

/// Uses the real Pubky client stack (pkarr + reqwest), so it needs access to the mainline DHT.
#[tokio::test]
async fn pubky_tls_is_terminated_and_forwarded_to_http_backend() -> Result<()> {
    let keypair = Keypair::random();
    let http_backend = start_http_echo_backend().await?;
    let proxy = Proxy::start(ProxyConfig {
        keypair: keypair.clone(),
        plain_http: false,
        ..proxy_config(http_backend, None, true)
    })
    .await?;
    let proxy_port = proxy.listen_addrs()[0].port();
    let client = pubky_http_client_for(&keypair, proxy_port).await?;

    let response = client
        .post(format!(
            "https://{}:{proxy_port}",
            keypair.public_key().to_z32()
        ))
        .body("Hello from client!")
        .send()
        .await
        .context("Failed to send request via proxy")?;

    assert!(response.status().is_success());
    let proxy_header = response.headers()["x-proxy-header"].to_str()?.to_string();
    assert!(
        proxy_header.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{proxy_header}"
    );
    assert_eq!(response.text().await?, "Hello from client!");

    proxy.shutdown(None).await
}

/// Uses the real Pubky client stack (pkarr + reqwest), so it needs access to the mainline DHT.
#[tokio::test]
async fn pubky_tls_with_backend_down_gets_bad_gateway() -> Result<()> {
    let keypair = Keypair::random();
    let proxy = Proxy::start(ProxyConfig {
        keypair: keypair.clone(),
        ..proxy_config(unused_localhost_addr(), None, true)
    })
    .await?;
    let proxy_port = proxy.listen_addrs()[0].port();
    let client = pubky_http_client_for(&keypair, proxy_port).await?;

    let response = client
        .post(format!(
            "https://{}:{proxy_port}",
            keypair.public_key().to_z32()
        ))
        .body("Hello from client!")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("Failed to get response from proxy")?;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body = response.text().await?;
    assert!(body.contains("Backend connection error"), "{body}");

    proxy.shutdown(None).await
}

// ---------------------------------------------------------------------------------------
// Proxy setup
// ---------------------------------------------------------------------------------------

fn proxy_config(
    http_backend_addr: SocketAddr,
    https_backend_addr: Option<SocketAddr>,
    send_proxy_protocol: bool,
) -> ProxyConfig {
    ProxyConfig {
        keypair: Keypair::random(),
        listen_addrs: vec![localhost_any_port()],
        http_backend_addr,
        https_backend_addr,
        plain_http: true,
        send_proxy_protocol,
        limits: ConnectionLimits::default(),
    }
}

async fn start_proxy(
    http_backend_addr: SocketAddr,
    https_backend_addr: Option<SocketAddr>,
    send_proxy_protocol: bool,
) -> Result<Proxy> {
    Proxy::start(proxy_config(
        http_backend_addr,
        https_backend_addr,
        send_proxy_protocol,
    ))
    .await
}

fn localhost_any_port() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn unused_localhost_addr() -> SocketAddr {
    let port = portpicker::pick_unused_port().expect("a free port is available");
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Publishes the proxy's address for `keypair` and returns a Pubky-capable HTTP client.
async fn pubky_http_client_for(keypair: &Keypair, proxy_port: u16) -> Result<reqwest::Client> {
    let root_name = Name::new(".")?;
    let mut svcb = SVCB::new(0, root_name.clone());
    svcb.set_port(proxy_port);
    let packet = pkarr::SignedPacket::builder()
        .a(root_name.clone(), "127.0.0.1".parse()?, 300)
        .https(root_name, svcb, 60 * 60)
        .build(keypair)?;

    let pkarr_client = pkarr::Client::builder().build()?;
    pkarr_client.publish(&packet).await?;

    Ok(reqwest::ClientBuilder::from(pkarr_client).build()?)
}

// ---------------------------------------------------------------------------------------
// Test clients and backends
// ---------------------------------------------------------------------------------------

/// Sends a minimal HTTP POST and returns the complete response.
async fn send_http_post(stream: &mut TcpStream, body: &str) -> Result<String> {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

/// Starts an HTTP backend that answers every request with its body and reports the PROXY
/// protocol header it received in the `x-proxy-header` response header (`none` if absent).
async fn start_http_echo_backend() -> Result<SocketAddr> {
    let listener = TcpListener::bind(localhost_any_port()).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (proxy_header, body) = read_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     x-proxy-header: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    body.len(),
                    proxy_header.as_deref().unwrap_or("none"),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(addr)
}

/// Reads one HTTP request, optionally preceded by a PROXY header line.
/// Returns the PROXY header (without line ending) and the request body.
async fn read_http_request(stream: &mut TcpStream) -> (Option<String>, String) {
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(position) = find(&received, b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return (None, String::new()),
            Ok(byte_count) => received.extend_from_slice(&chunk[..byte_count]),
        }
    };

    let head = String::from_utf8_lossy(&received[..head_end]).to_string();
    let proxy_header = head
        .lines()
        .next()
        .filter(|first_line| first_line.starts_with("PROXY "))
        .map(str::to_string);
    let content_length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0);

    while received.len() < head_end + content_length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(byte_count) => received.extend_from_slice(&chunk[..byte_count]),
        }
    }
    let body = String::from_utf8_lossy(&received[head_end..]).to_string();

    (proxy_header, body)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A backend that accepts one connection and records the raw bytes it receives.
struct RecordingBackend {
    listener: TcpListener,
}

impl RecordingBackend {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind(localhost_any_port()).await?;
        Ok(Self { listener })
    }

    fn addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Waits for a connection and returns its first `byte_count` bytes.
    async fn receive(self, byte_count: usize) -> Result<Vec<u8>> {
        let receive_bytes = async {
            let (mut stream, _) = self.listener.accept().await?;
            let mut received = vec![0u8; byte_count];
            stream.read_exact(&mut received).await?;
            anyhow::Ok(received)
        };
        tokio::time::timeout(Duration::from_secs(5), receive_bytes)
            .await
            .context("Timed out waiting for bytes at the recording backend")?
    }
}
