use anyhow::{Context, Result};
use clap::Parser;
use pkarr::Keypair;
use std::{io::IsTerminal, time::Duration};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;
mod dns_records;
mod forwarding;
mod init;
mod packet_cache;
mod prefixed_stream;
mod proxy;
mod proxy_protocol;
mod publisher;
mod secret;
#[cfg(test)]
mod test_support;
mod traffic_detection;

use config::{PkarrPublishSettings, Settings};
use packet_cache::PacketCache;
use proxy::{Proxy, ProxyConfig};
use publisher::{PkarrNetwork, PkarrPublisher};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = cli::Args::parse();
    if let Some(cli::Command::Init(init_args)) = &args.command {
        return init::run(init_args).await;
    }
    let check = args.check;
    let settings = Settings::load(args)?;
    let records = settings
        .dns_records_file
        .as_ref()
        .map(|path| dns_records::DnsRecords::load(path))
        .transpose()?;
    if check {
        let keypair = match secret::check_keypair(&settings.secret_key_file)? {
            Some(keypair) => keypair,
            None => {
                info!(
                    "Secret key file {:?} is missing; startup will generate it",
                    settings.secret_key_file
                );
                Keypair::random()
            }
        };
        if let Some(records) = &records {
            records.sign(&keypair, None)?;
        }
        info!("Configuration and DNS records are valid");
        return Ok(());
    }
    match &settings.config_file {
        Some(config_file) => info!("Using config file {config_file:?}"),
        None => info!("No config file found, using command line arguments and defaults"),
    }
    let keypair = secret::load_or_create_keypair(&settings.secret_key_file)?;
    if let Some(records) = &records {
        records.sign(&keypair, None)?;
    }

    let proxy = Proxy::start(ProxyConfig {
        keypair: keypair.clone(),
        listen_addrs: settings.listen_addrs.clone(),
        http_backend_addr: settings.http_backend_addr,
        tls_passthrough_backend_addr: settings.tls_passthrough_backend_addr,
        plain_http: settings.plain_http,
        send_proxy_protocol: settings.send_proxy_protocol,
        limits: settings.limits,
    })
    .await?;
    log_proxy_settings(&proxy, &settings);

    let publisher = match &settings.pkarr_publish {
        Some(publish_settings) => Some(start_pkarr_publisher(&keypair, publish_settings, records)?),
        None => {
            info!("PKARR publishing and republishing: off");
            None
        }
    };

    wait_for_shutdown_signal().await?;
    info!("Received shutdown signal, shutting down...");

    // Stop both services together; a publisher error must not skip connection draining.
    let stop_publisher = async {
        if let Some(publisher) = publisher {
            publisher.shutdown(Some(SHUTDOWN_TIMEOUT)).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let (proxy_result, publisher_result) =
        tokio::join!(proxy.shutdown(Some(SHUTDOWN_TIMEOUT)), stop_publisher);
    proxy_result?;
    publisher_result?;
    info!("Shutdown complete.");

    Ok(())
}

/// Registers shutdown handlers before announcing readiness to receive a signal.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt()).context("Failed to listen for SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("Failed to listen for SIGTERM")?;
    info!("Press Ctrl+C to stop the proxy (SIGTERM also supported)");
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<()> {
    info!("Press Ctrl+C to stop the proxy");
    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C")
}

/// Default log filter when `RUST_LOG` isn't set. rustls warns about clients that break the
/// TLS spec (e.g. an IP address as SNI), which operators can't act on.
const DEFAULT_LOG_FILTER: &str = "info,rustls=error";

/// Logs according to `RUST_LOG` (e.g. `RUST_LOG=pubky_tls_proxy=debug`), or
/// [`DEFAULT_LOG_FILTER`] if it isn't set.
/// Colours are only used on a terminal, so they don't end up in e.g. the systemd journal.
fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}

fn log_proxy_settings(proxy: &Proxy, settings: &Settings) {
    info!("Using public key: {}", proxy.public_key());
    for listen_addr in proxy.listen_addrs() {
        info!("Listening on {listen_addr}");
    }
    if settings.plain_http {
        info!("Plain HTTP -> {}", settings.http_backend_addr);
    } else {
        info!("Plain HTTP -> rejected");
    }
    info!("Raw public key TLS -> {}", settings.http_backend_addr);
    match settings.tls_passthrough_backend_addr {
        Some(addr) => info!("TLS passthrough -> {addr}"),
        None => info!("TLS passthrough -> rejected, no TLS passthrough backend configured"),
    }
    let proxy_protocol_state = if settings.send_proxy_protocol {
        "on"
    } else {
        "off"
    };
    info!("PROXY protocol header: {proxy_protocol_state}");
}

fn start_pkarr_publisher(
    keypair: &Keypair,
    settings: &PkarrPublishSettings,
    records: Option<dns_records::DnsRecords>,
) -> Result<PkarrPublisher> {
    let mut networks = Vec::new();
    match &settings.dht_bootstrap_nodes {
        Some(bootstrap_nodes) => {
            info!("PKARR publishing to the DHT, bootstrapping via {bootstrap_nodes:?}");
            networks.push(PkarrNetwork::dht(bootstrap_nodes)?);
        }
        None => info!("PKARR publishing to the DHT: off"),
    }
    match &settings.relay_urls {
        Some(relay_urls) => {
            let relay_list: Vec<&str> = relay_urls.iter().map(|relay| relay.as_str()).collect();
            info!("PKARR publishing to relays {relay_list:?}");
            networks.push(PkarrNetwork::relays(relay_urls)?);
        }
        None => info!("PKARR publishing to relays: off"),
    }
    info!(
        "Republishing the PKARR packet every {}s",
        settings.republish_interval.as_secs()
    );
    info!(
        "Caching the PKARR packet in {:?}",
        settings.packet_cache_file
    );
    let cache = PacketCache::new(settings.packet_cache_file.clone(), keypair.public_key());

    Ok(match (records, &settings.dns_records_file) {
        (Some(records), Some(path)) => PkarrPublisher::start_local_records(
            keypair.clone(),
            networks,
            cache,
            settings.republish_interval,
            path.clone(),
            records,
        ),
        _ => PkarrPublisher::start_external_packet(
            keypair.public_key(),
            networks,
            cache,
            settings.republish_interval,
        ),
    })
}
