//! Keeps the pkarr packet of our public key alive by republishing it periodically.
//!
//! DHT nodes and relays drop packets after a while unless they are published again. The
//! republisher resolves the most recent packet and publishes it again unchanged: same
//! records, signature and timestamp. It never creates or re-signs a packet, so the packet
//! must have been published by something else first.

use anyhow::{Context, Result};
use futures_util::future::join_all;
use pkarr::{errors::PublishError, PublicKey, SignedPacket, Timestamp};
use std::{net::SocketAddrV4, time::Duration};
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, error, info, warn};
use url::Url;

/// Waits before retrying a failed publish on one network.
const PUBLISH_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(60), Duration::from_secs(5 * 60)];

/// One pkarr network that packets are resolved from and republished to.
///
/// Every network gets its own client: with both DHT and relays enabled,
/// `pkarr::Client::publish` returns whichever finishes first, even a failure, and cancels
/// the other. Separate clients make sure each network is published to and reported on.
pub struct PkarrNetwork {
    name: &'static str,
    client: pkarr::Client,
}

impl PkarrNetwork {
    /// The mainline DHT, joined through `bootstrap_nodes`.
    pub fn dht(bootstrap_nodes: &[SocketAddrV4]) -> Result<Self> {
        let client = pkarr::Client::builder()
            .no_relays()
            .bootstrap(bootstrap_nodes)
            .build()
            .context("Failed to create pkarr DHT client")?;
        Ok(Self {
            name: "DHT",
            client,
        })
    }

    /// The given pkarr relays.
    pub fn relays(relays: &[Url]) -> Result<Self> {
        let client = pkarr::Client::builder()
            .no_dht()
            .relays(relays)
            .context("Invalid pkarr relay URL")?
            .build()
            .context("Failed to create pkarr relays client")?;
        Ok(Self {
            name: "relays",
            client,
        })
    }

    /// Waits until a DHT client has joined the network. Returns right away for relays.
    ///
    /// Right after start the DHT routing table is empty, so resolving finds nothing and
    /// publishing fails with "no closest nodes".
    async fn wait_until_ready(&self) {
        let Some(dht) = self.client.dht() else {
            return;
        };
        if dht.as_async().bootstrapped().await {
            debug!("{} bootstrapped", self.name);
        } else {
            warn!("Could not bootstrap the {}. Check the bootstrap nodes and that outgoing UDP is allowed.", self.name);
        }
    }
}

/// What a single republish run achieved.
#[derive(Debug, PartialEq, Eq)]
pub enum RepublishOutcome {
    /// No network returned a packet for the public key.
    NotFound,
    /// The packet with `timestamp` was republished. Networks are listed by name.
    Republished {
        timestamp: Timestamp,
        succeeded: Vec<&'static str>,
        /// Networks that rejected the packet because they hold a newer one.
        have_newer_packet: Vec<&'static str>,
        failed: Vec<&'static str>,
    },
}

/// Result of publishing to one network.
enum PublishResult {
    Published,
    /// The network rejected the packet with a pkarr concurrency error: it holds a newer or
    /// conflicting packet. Retrying the same packet can't succeed.
    NewerPacketExists(PublishError),
    Failed(PublishError),
}

/// Resolves the most recent packet of `public_key` from all `networks` and publishes it
/// unchanged to each of them.
///
/// A failed publish is retried on that network after each of `retry_delays`, unless the
/// network holds a newer packet. Networks are published to concurrently, so retries on one
/// don't delay the others. Failures are logged here; the outcome only lists the networks.
pub async fn republish_once(
    public_key: &PublicKey,
    networks: &[PkarrNetwork],
    retry_delays: &[Duration],
) -> RepublishOutcome {
    let Some(packet) = resolve_most_recent(public_key, networks).await else {
        return RepublishOutcome::NotFound;
    };

    let publish_results = join_all(
        networks
            .iter()
            .map(|network| publish_with_retries(network, &packet, retry_delays)),
    )
    .await;

    let mut succeeded = Vec::new();
    let mut have_newer_packet = Vec::new();
    let mut failed = Vec::new();
    for (network, result) in networks.iter().zip(publish_results) {
        match result {
            PublishResult::Published => succeeded.push(network.name),
            PublishResult::NewerPacketExists(error) => {
                info!(
                    "{} rejected the pkarr packet because it holds a newer one: {error}",
                    network.name
                );
                have_newer_packet.push(network.name);
            }
            PublishResult::Failed(error) => {
                error!(
                    "Republishing pkarr packet to {} failed after {} retries: {error}",
                    network.name,
                    retry_delays.len()
                );
                failed.push(network.name);
            }
        }
    }

    RepublishOutcome::Republished {
        timestamp: packet.timestamp(),
        succeeded,
        have_newer_packet,
        failed,
    }
}

/// Resolving can't tell "no packet" from "network unreachable": both return `None`.
async fn resolve_most_recent(
    public_key: &PublicKey,
    networks: &[PkarrNetwork],
) -> Option<SignedPacket> {
    let resolved_packets = join_all(
        networks
            .iter()
            .map(|network| network.client.resolve_most_recent(public_key)),
    )
    .await;

    for (network, packet) in networks.iter().zip(&resolved_packets) {
        match packet {
            Some(packet) => debug!(
                "{} returned the pkarr packet signed at {} (Unix µs)",
                network.name,
                packet.timestamp().as_u64()
            ),
            None => debug!("{} returned no pkarr packet", network.name),
        }
    }

    resolved_packets
        .into_iter()
        .flatten()
        .max_by_key(SignedPacket::timestamp)
}

async fn publish_with_retries(
    network: &PkarrNetwork,
    packet: &SignedPacket,
    retry_delays: &[Duration],
) -> PublishResult {
    let mut result = publish(network, packet).await;
    for delay in retry_delays {
        let PublishResult::Failed(error) = &result else {
            break;
        };
        warn!(
            "Republishing pkarr packet to {} failed: {error}. Retrying in {}s.",
            network.name,
            delay.as_secs()
        );
        tokio::time::sleep(*delay).await;
        result = publish(network, packet).await;
    }
    result
}

async fn publish(network: &PkarrNetwork, packet: &SignedPacket) -> PublishResult {
    match network.client.publish(packet, None).await {
        Ok(()) => PublishResult::Published,
        Err(error @ PublishError::Concurrency(_)) => PublishResult::NewerPacketExists(error),
        Err(error) => PublishResult::Failed(error),
    }
}

/// Republishes the packet of a public key in the background: right after start, then every
/// `interval`, until [`Republisher::shutdown`].
pub struct Republisher {
    task: JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl Republisher {
    pub fn start(public_key: PublicKey, networks: Vec<PkarrNetwork>, interval: Duration) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(republish_periodically(
            public_key,
            networks,
            interval,
            shutdown_rx,
        ));
        Self { task, shutdown_tx }
    }

    /// Stops republishing, also in the middle of a run.
    ///
    /// # Errors
    ///
    /// Fails if the background task doesn't stop within `timeout` (default 10 seconds).
    pub async fn shutdown(self, timeout: Option<Duration>) -> Result<()> {
        // Sending only fails if the task is already gone, which is fine.
        let _ = self.shutdown_tx.send(true);

        let timeout = timeout.unwrap_or(Duration::from_secs(10));
        tokio::time::timeout(timeout, self.task)
            .await
            .with_context(|| format!("Republisher shutdown timed out after {timeout:?}"))?
            .context("Republisher task failed")
    }
}

async fn republish_periodically(
    public_key: PublicKey,
    networks: Vec<PkarrNetwork>,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let all_networks_ready = join_all(networks.iter().map(PkarrNetwork::wait_until_ready));
    tokio::select! {
        _ = all_networks_ready => {}
        _ = shutdown_rx.changed() => return,
    }

    loop {
        // Both awaits are raced against shutdown, so a run in progress (e.g. waiting for a
        // retry) is cancelled as well.
        tokio::select! {
            outcome = republish_once(&public_key, &networks, &PUBLISH_RETRY_DELAYS) => {
                log_outcome(&public_key, &outcome);
            }
            _ = shutdown_rx.changed() => break,
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown_rx.changed() => break,
        }
    }
}

fn log_outcome(public_key: &PublicKey, outcome: &RepublishOutcome) {
    match outcome {
        RepublishOutcome::NotFound => warn!(
            "No pkarr packet found for {public_key}, nothing to republish. \
             Publish one first, or check the network connection."
        ),
        RepublishOutcome::Republished {
            succeeded,
            have_newer_packet,
            ..
        } if succeeded.is_empty() && have_newer_packet.is_empty() => {
            error!("Republishing the pkarr packet for {public_key} failed on all networks");
        }
        RepublishOutcome::Republished { succeeded, .. } if succeeded.is_empty() => {
            info!("Nothing republished for {public_key}: the networks hold a newer packet");
        }
        RepublishOutcome::Republished {
            timestamp,
            succeeded,
            ..
        } => {
            let packet_age_secs =
                Timestamp::now().as_u64().saturating_sub(timestamp.as_u64()) / 1_000_000;
            info!(
                "Republished pkarr packet for {public_key} (signed {packet_age_secs}s ago) to: {}",
                succeeded.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::{mainline::Testnet, Keypair};

    /// A local DHT, so tests don't need internet access.
    struct LocalDht {
        testnet: Testnet,
    }

    impl LocalDht {
        async fn start() -> Self {
            let testnet = Testnet::new_async(5).await.expect("local testnet starts");
            Self { testnet }
        }

        fn network(&self) -> PkarrNetwork {
            let bootstrap_nodes: Vec<SocketAddrV4> = self
                .testnet
                .bootstrap
                .iter()
                .map(|node| {
                    node.parse()
                        .expect("testnet nodes are IPv4 socket addresses")
                })
                .collect();
            PkarrNetwork::dht(&bootstrap_nodes).unwrap()
        }

        async fn publish(&self, packet: &SignedPacket) {
            self.network().client.publish(packet, None).await.unwrap();
        }

        async fn resolve(&self, public_key: &PublicKey) -> Option<SignedPacket> {
            self.network().client.resolve_most_recent(public_key).await
        }
    }

    fn signed_packet(keypair: &Keypair) -> SignedPacket {
        signed_packet_with_text(keypair, "hello")
    }

    /// Packets signed later get a later timestamp.
    fn signed_packet_with_text(keypair: &Keypair, text: &str) -> SignedPacket {
        SignedPacket::builder()
            .txt("_demo".try_into().unwrap(), text.try_into().unwrap(), 300)
            .sign(keypair)
            .unwrap()
    }

    fn unreachable_relay() -> PkarrNetwork {
        let port = portpicker::pick_unused_port().expect("a free port is available");
        PkarrNetwork::relays(&[format!("http://127.0.0.1:{port}").parse().unwrap()]).unwrap()
    }

    #[tokio::test]
    async fn found_packet_is_republished_unchanged() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        dht.publish(&packet).await;

        let outcome = republish_once(&keypair.public_key(), &[dht.network()], &[]).await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                succeeded: vec!["DHT"],
                have_newer_packet: vec![],
                failed: vec![],
            }
        );
        let resolved = dht.resolve(&keypair.public_key()).await.unwrap();
        assert_eq!(resolved.as_bytes(), packet.as_bytes());
    }

    #[tokio::test]
    async fn unknown_public_key_is_not_found() {
        let dht = LocalDht::start().await;
        let unknown_public_key = Keypair::random().public_key();

        let outcome = republish_once(&unknown_public_key, &[dht.network()], &[]).await;

        assert_eq!(outcome, RepublishOutcome::NotFound);
    }

    #[tokio::test]
    async fn failing_network_does_not_prevent_publishing_to_the_others() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        dht.publish(&packet).await;
        let networks = [dht.network(), unreachable_relay()];

        let outcome = republish_once(
            &keypair.public_key(),
            &networks,
            &[Duration::from_millis(10)],
        )
        .await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                succeeded: vec!["DHT"],
                have_newer_packet: vec![],
                failed: vec!["relays"],
            }
        );
    }

    #[tokio::test]
    async fn network_holding_a_newer_packet_is_not_retried() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let older_packet = signed_packet_with_text(&keypair, "older");
        let newer_packet = signed_packet_with_text(&keypair, "newer");
        dht.publish(&newer_packet).await;

        let result =
            publish_with_retries(&dht.network(), &older_packet, &[Duration::from_secs(3600)]).await;

        assert!(matches!(result, PublishResult::NewerPacketExists(_)));
    }
}
