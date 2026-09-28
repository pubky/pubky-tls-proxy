use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{fs, path::Path, time::Duration};
use tokio::signal;
use tracing::{info, Level};

mod cli;
mod config;
mod forwarding;
mod prefixed_stream;
mod proxy;
mod proxy_protocol;
mod republisher;
#[cfg(test)]
mod test_support;
mod traffic_detection;

use config::{RepublishSettings, Settings};
use proxy::{Proxy, ProxyConfig};
use republisher::{PkarrNetwork, Republisher};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let settings = Settings::load(cli::Args::parse())?;
    match &settings.config_file {
        Some(config_file) => info!("Using config file {config_file:?}"),
        None => info!("No config file found, using command line arguments and defaults"),
    }
    let keypair = read_keypair(&settings.secret_file)?;

    let proxy = Proxy::start(ProxyConfig {
        keypair: keypair.clone(),
        listen_addrs: settings.listen_addrs.clone(),
        http_backend_addr: settings.http_backend_addr,
        https_backend_addr: settings.https_backend_addr,
        send_proxy_protocol: settings.send_proxy_protocol,
    })
    .await?;
    log_proxy_settings(&proxy, &settings);

    let republisher = match &settings.republish {
        Some(republish) => Some(start_republisher(&keypair, republish)?),
        None => {
            info!("Republishing the pkarr packet: off");
            None
        }
    };

    info!("Press Ctrl+C to stop the proxy");
    signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C")?;
    info!("Received shutdown signal, shutting down...");

    if let Some(republisher) = republisher {
        republisher.shutdown(Some(SHUTDOWN_TIMEOUT)).await?;
    }
    proxy.shutdown(Some(SHUTDOWN_TIMEOUT)).await?;
    info!("Shutdown complete.");

    Ok(())
}

fn log_proxy_settings(proxy: &Proxy, settings: &Settings) {
    info!("Using public key: {}", proxy.public_key());
    for listen_addr in proxy.listen_addrs() {
        info!("Listening on {listen_addr}");
    }
    info!("Plain HTTP and Pubky TLS -> {}", settings.http_backend_addr);
    match settings.https_backend_addr {
        Some(https_backend_addr) => info!("Regular HTTPS -> {https_backend_addr}"),
        None => info!("Regular HTTPS -> rejected, no HTTPS backend configured"),
    }
    let proxy_protocol_state = if settings.send_proxy_protocol {
        "on"
    } else {
        "off"
    };
    info!("PROXY protocol header: {proxy_protocol_state}");
}

fn start_republisher(keypair: &Keypair, republish: &RepublishSettings) -> Result<Republisher> {
    let mut networks = Vec::new();
    match &republish.dht_bootstrap_nodes {
        Some(bootstrap_nodes) => {
            info!("Republishing to the DHT, bootstrapping via {bootstrap_nodes:?}");
            networks.push(PkarrNetwork::dht(bootstrap_nodes)?);
        }
        None => info!("Republishing to the DHT: off"),
    }
    match &republish.relays {
        Some(relays) => {
            let relay_list: Vec<&str> = relays.iter().map(|relay| relay.as_str()).collect();
            info!("Republishing to relays {relay_list:?}");
            networks.push(PkarrNetwork::relays(relays)?);
        }
        None => info!("Republishing to relays: off"),
    }
    info!(
        "Republishing the pkarr packet every {}s",
        republish.interval.as_secs()
    );

    Ok(Republisher::start(
        keypair.public_key(),
        networks,
        republish.interval,
    ))
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
