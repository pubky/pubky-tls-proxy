use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::signal;
use tracing::{info, Level};

mod forwarding;
mod prefixed_stream;
mod proxy;
mod proxy_protocol;
#[cfg(test)]
mod test_support;
mod traffic_detection;

use proxy::{Proxy, ProxyConfig};

/// A proxy that terminates Pubky TLS with a pkarr secret key and routes all other HTTP(S)
/// traffic to a regular web server such as nginx.
///
/// Plain HTTP and decrypted Pubky TLS go to the HTTP backend. Regular HTTPS is passed through
/// to the HTTPS backend without decrypting it.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the file containing the pkarr secret key in HEX format.
    #[arg(long, value_name = "FILE")]
    secret_file: PathBuf,

    /// Address to listen on for incoming connections. Can be repeated (e.g. for ports 80 and 443).
    #[arg(
        long = "listen-addr",
        value_name = "ADDR",
        default_value = "0.0.0.0:8443"
    )]
    listen_addrs: Vec<SocketAddr>,

    /// Backend for plain HTTP and decrypted Pubky TLS traffic.
    #[arg(
        long,
        alias = "backend-addr",
        value_name = "ADDR",
        default_value = "127.0.0.1:6286"
    )]
    http_backend_addr: SocketAddr,

    /// Backend for regular HTTPS traffic, which is forwarded still encrypted.
    /// If not set, regular HTTPS connections are closed.
    #[arg(long, value_name = "ADDR")]
    https_backend_addr: Option<SocketAddr>,

    /// Don't send a PROXY protocol v1 header to the backends.
    /// Use this if the backend doesn't understand the PROXY protocol.
    #[arg(long)]
    no_proxy_protocol: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();
    let keypair = read_keypair(&args.secret_file)?;

    let proxy = Proxy::start(ProxyConfig {
        keypair,
        listen_addrs: args.listen_addrs,
        http_backend_addr: args.http_backend_addr,
        https_backend_addr: args.https_backend_addr,
        send_proxy_protocol: !args.no_proxy_protocol,
    })
    .await?;

    info!("Using public key: {}", proxy.public_key());
    for listen_addr in proxy.listen_addrs() {
        info!("Listening on {listen_addr}");
    }
    info!("Plain HTTP and Pubky TLS -> {}", args.http_backend_addr);
    match args.https_backend_addr {
        Some(https_backend_addr) => info!("Regular HTTPS -> {https_backend_addr}"),
        None => info!("Regular HTTPS -> rejected, no --https-backend-addr configured"),
    }
    info!(
        "PROXY protocol header: {}",
        if args.no_proxy_protocol { "off" } else { "on" }
    );

    info!("Press Ctrl+C to stop the proxy");
    signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C")?;
    info!("Received shutdown signal, shutting down...");

    proxy.shutdown(Some(Duration::from_secs(5))).await?;
    info!("Shutdown complete.");

    Ok(())
}

/// Reads a pkarr keypair from a file containing the 32-byte secret key as hex.
fn read_keypair(secret_file: &Path) -> Result<Keypair> {
    let path = secret_file
        .canonicalize()
        .with_context(|| format!("Failed to get absolute path for: {secret_file:?}"))?;

    info!("Loading secret file from {path:?}");
    let secret_hex = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read secret file: {path:?}"))?;
    let secret_bytes = hex::decode(secret_hex.trim()).context("Failed to decode hex secret key")?;
    let secret_key: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Secret key must be exactly 32 bytes (64 hex chars)"))?;

    Ok(Keypair::from_secret_key(&secret_key))
}
