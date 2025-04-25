use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{fs, net::SocketAddr, path::PathBuf};
use tokio::{
    signal,
    sync::oneshot,
};
use tracing::{error, info, Level};
use tracing_subscriber;

mod proxy;
use proxy::TlsProxy;

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

