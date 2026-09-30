//! Publishes DNS records in local-records mode or republishes a PKARR packet in external-packet mode.
//!
//! DHT nodes and relays drop packets after a while unless they are published again.
//! Without a DNS records file, the publisher resolves the most recent PKARR packet and
//! republishes it unchanged. With a DNS records file, it signs the complete local record
//! set and publishes valid edits promptly.

use crate::{dns_records::DnsRecords, packet_cache::PacketCache};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use pkarr::{
    errors::{PublishError, ResolveError},
    Keypair, PublicKey, ResolvePolicy, SignedPacket, Timestamp,
};
use std::{
    net::SocketAddrV4,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, error, info, warn};
use url::Url;

/// Waits before retrying a failed resolve or a failed publish on one network.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(60), Duration::from_secs(5 * 60)];

/// Resolving with `ResolvePolicy::NetworkOnly` makes a relay run a full DHT query, which
/// often takes longer than PKARR's default request timeout of 2 seconds.
const RELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// One PKARR network that packets are resolved from and published or republished to.
///
/// Every network gets its own client. A `pkarr::Client` with both DHT and relays reports a
/// single combined result, so it wouldn't tell which network failed or needs a retry.
pub struct PkarrNetwork {
    name: &'static str,
    client: pkarr::Client,
}

impl PkarrNetwork {
    /// The Mainline DHT, joined through `bootstrap_nodes`.
    pub fn dht(bootstrap_nodes: &[SocketAddrV4]) -> Result<Self> {
        let client = pkarr::Client::builder()
            .no_relays()
            .bootstrap(bootstrap_nodes)
            .build()
            .context("Failed to create PKARR DHT client")?;
        Ok(Self {
            name: "DHT",
            client,
        })
    }

    /// The given PKARR relays.
    pub fn relays(relays: &[Url]) -> Result<Self> {
        let client = pkarr::Client::builder()
            .no_dht()
            .relays(relays)
            .context("Invalid PKARR relay URL")?
            .request_timeout(RELAY_REQUEST_TIMEOUT)
            .build()
            .context("Failed to create PKARR relays client")?;
        Ok(Self {
            name: "relays",
            client,
        })
    }
}

/// What a single republish run achieved.
#[derive(Debug, PartialEq, Eq)]
pub enum RepublishOutcome {
    /// Every network answered that it has no packet for the public key, and none is cached.
    NotFound,
    /// No network returned a packet, at least one couldn't be asked, and none is cached.
    ResolveFailed,
    /// The packet with `timestamp` was republished. Networks are listed by name.
    Republished {
        timestamp: Timestamp,
        source: PacketSource,
        succeeded: Vec<&'static str>,
        /// Networks that rejected the packet because they hold a newer one.
        have_newer_packet: Vec<&'static str>,
        failed: Vec<&'static str>,
    },
}

/// Where the republished packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSource {
    Networks,
    /// The networks returned no packet, or an older one than the cached copy.
    Cache,
}

/// Result of resolving the packet from all networks.
enum ResolveResult {
    Found(SignedPacket),
    NotFound,
    Failed,
}

impl ResolveResult {
    fn packet(&self) -> Option<SignedPacket> {
        match self {
            ResolveResult::Found(packet) => Some(packet.clone()),
            ResolveResult::NotFound | ResolveResult::Failed => None,
        }
    }
}

/// Result of publishing to one network.
enum PublishResult {
    Published,
    /// The network holds a newer packet. Retrying the same packet can't succeed.
    NewerPacketExists,
    Failed(PublishError),
}

/// Publishes the most recent packet of `public_key` unchanged to all `networks`.
///
/// The most recent packet is the newest of what the networks return and the copy in
/// `cache`. A newer packet from the networks replaces the cached copy.
///
/// Resolving is retried after each of `retry_delays` if no network could be asked. A failed
/// publish is retried on that network, unless the network holds a newer packet. Networks
/// are published to concurrently, so retries on one don't delay the others. Failures are
/// logged here; the outcome only lists the networks.
pub async fn republish_once(
    public_key: &PublicKey,
    networks: &[PkarrNetwork],
    cache: &PacketCache,
    retry_delays: &[Duration],
) -> RepublishOutcome {
    let resolved = resolve_with_retries(public_key, networks, retry_delays).await;
    let cached_packet = cache.load().await;

    let Some((packet, source)) = most_recent_packet(resolved.packet(), cached_packet.clone())
    else {
        // Nothing to republish. It's only "not found" if every network could be asked.
        return match resolved {
            ResolveResult::Failed => RepublishOutcome::ResolveFailed,
            ResolveResult::Found(_) | ResolveResult::NotFound => RepublishOutcome::NotFound,
        };
    };

    match source {
        PacketSource::Networks => update_cache(cache, &packet, cached_packet.as_ref()).await,
        PacketSource::Cache => warn!(
            "The networks returned no PKARR packet or an older one. \
             Republishing the cached packet from {:?}.",
            cache.path()
        ),
    }

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
            PublishResult::NewerPacketExists => {
                info!(
                    "{} holds a newer PKARR packet than the one found",
                    network.name
                );
                have_newer_packet.push(network.name);
            }
            PublishResult::Failed(error) => {
                error!(
                    "Republishing PKARR packet to {} failed after {} retries: {error}",
                    network.name,
                    retry_delays.len()
                );
                failed.push(network.name);
            }
        }
    }

    RepublishOutcome::Republished {
        timestamp: packet.timestamp(),
        source,
        succeeded,
        have_newer_packet,
        failed,
    }
}

/// Picks the newer of the packet from the networks and the cached one. If both are the same
/// packet, the networks win.
fn most_recent_packet(
    network_packet: Option<SignedPacket>,
    cached_packet: Option<SignedPacket>,
) -> Option<(SignedPacket, PacketSource)> {
    match (network_packet, cached_packet) {
        (Some(network_packet), Some(cached_packet))
            if cached_packet.more_recent_than(&network_packet) =>
        {
            Some((cached_packet, PacketSource::Cache))
        }
        (Some(network_packet), _) => Some((network_packet, PacketSource::Networks)),
        (None, Some(cached_packet)) => Some((cached_packet, PacketSource::Cache)),
        (None, None) => None,
    }
}

/// Stores `packet` in the cache unless the cache already holds it. A cache that can't be
/// written is logged; republishing continues without it.
async fn update_cache(
    cache: &PacketCache,
    packet: &SignedPacket,
    cached_packet: Option<&SignedPacket>,
) {
    let is_newer_than_cache = cached_packet.is_none_or(|cached| packet.more_recent_than(cached));
    if !is_newer_than_cache {
        return;
    }

    match cache.store(packet).await {
        Ok(()) => info!("Cached the PKARR packet in {:?}", cache.path()),
        Err(error) => warn!(
            "Can't cache the PKARR packet in {:?}: {error}",
            cache.path()
        ),
    }
}

async fn resolve_with_retries(
    public_key: &PublicKey,
    networks: &[PkarrNetwork],
    retry_delays: &[Duration],
) -> ResolveResult {
    let mut result = resolve_most_recent(public_key, networks).await;
    for delay in retry_delays {
        let ResolveResult::Failed = result else {
            break;
        };
        warn!(
            "Resolving the PKARR packet failed. Retrying in {}s.",
            delay.as_secs()
        );
        tokio::time::sleep(*delay).await;
        result = resolve_most_recent(public_key, networks).await;
    }
    result
}

/// Asks all networks and keeps the most recent packet. Only "not found" from every network
/// counts as not found; any other error means we don't know.
async fn resolve_most_recent(public_key: &PublicKey, networks: &[PkarrNetwork]) -> ResolveResult {
    let results = join_all(networks.iter().map(|network| {
        network
            .client
            .resolve(public_key, ResolvePolicy::NetworkOnly)
    }))
    .await;

    let mut most_recent: Option<SignedPacket> = None;
    let mut has_failed_network = false;
    for (network, result) in networks.iter().zip(results) {
        match result {
            Ok(packet) => {
                debug!(
                    "{} returned the PKARR packet signed at {} (Unix µs)",
                    network.name,
                    packet.timestamp().as_u64()
                );
                if most_recent
                    .as_ref()
                    .is_none_or(|current| packet.more_recent_than(current))
                {
                    most_recent = Some(packet);
                }
            }
            Err(ResolveError::NotFound) => debug!("{} has no PKARR packet", network.name),
            Err(error) => {
                warn!(
                    "Resolving the PKARR packet from {} failed: {error}",
                    network.name
                );
                has_failed_network = true;
            }
        }
    }

    match most_recent {
        Some(packet) => ResolveResult::Found(packet),
        None if has_failed_network => ResolveResult::Failed,
        None => ResolveResult::NotFound,
    }
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
            "Republishing PKARR packet to {} failed: {error}. Retrying in {}s.",
            network.name,
            delay.as_secs()
        );
        tokio::time::sleep(*delay).await;
        result = publish(network, packet).await;
    }
    result
}

async fn publish(network: &PkarrNetwork, packet: &SignedPacket) -> PublishResult {
    match network.client.publish(packet).await {
        Ok(stored_node_count) => {
            debug!(
                "{} stored the PKARR packet on {stored_node_count} DHT nodes",
                network.name
            );
            PublishResult::Published
        }
        Err(PublishError::NotMostRecent) => PublishResult::NewerPacketExists,
        Err(error) => PublishResult::Failed(error),
    }
}

/// Publishes local DNS records or republishes an external PKARR packet in the background
/// until [`PkarrPublisher::shutdown`]. Both modes periodically republish the packet.
pub struct PkarrPublisher {
    task: JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl PkarrPublisher {
    /// Resolves and republishes an external PKARR packet at startup and each republish interval.
    pub fn start_external_packet(
        public_key: PublicKey,
        networks: Vec<PkarrNetwork>,
        cache: PacketCache,
        republish_interval: Duration,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(republish_periodically(
            public_key,
            networks,
            cache,
            republish_interval,
            shutdown_rx,
        ));
        Self { task, shutdown_tx }
    }

    /// Publishes the file's complete record set and checks for changes every three seconds.
    pub fn start_local_records(
        keypair: Keypair,
        networks: Vec<PkarrNetwork>,
        cache: PacketCache,
        republish_interval: Duration,
        dns_records_file: PathBuf,
        records: DnsRecords,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(publish_local_periodically(
            keypair,
            networks,
            cache,
            republish_interval,
            dns_records_file,
            records,
            shutdown_rx,
        ));
        Self { task, shutdown_tx }
    }

    /// Stops publishing and republishing, also in the middle of a run.
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
            .with_context(|| format!("PKARR publisher shutdown timed out after {timeout:?}"))?
            .context("PKARR publisher task failed")
    }
}

/// The last valid local packet is kept in memory even if an edit is invalid or the file
/// briefly disappears during replacement. Publication is cancelled when a new edit arrives.
async fn publish_local_periodically(
    keypair: Keypair,
    networks: Vec<PkarrNetwork>,
    cache: PacketCache,
    republish_interval: Duration,
    path: PathBuf,
    mut records: DnsRecords,
    mut shutdown: watch::Receiver<bool>,
) {
    info!("Managing {} DNS records from {path:?}", records.len());
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let cached = cache.load().await;
    let mut packet = match records.sign(&keypair, cached.as_ref().map(SignedPacket::timestamp)) {
        Ok(packet) => packet,
        Err(error) => {
            error!("Cannot sign {path:?}: {error:#}");
            return;
        }
    };
    let mut pending = true;
    let mut last_publish = tokio::time::Instant::now();
    loop {
        if pending || last_publish.elapsed() >= republish_interval {
            // Publishing to the networks is independent; retries on one never block the other.
            let changed = {
                let publication = publish_local(&keypair, &networks, &cache, &records, &mut packet);
                tokio::pin!(publication);
                loop {
                    tokio::select! {
                        completed = &mut publication => {
                            pending = !completed;
                            last_publish = tokio::time::Instant::now();
                            break None;
                        }
                        _ = ticker.tick() => {
                            if let Some(updated) = read_updated_records(&path, &records) {
                                break Some(updated);
                            }
                        }
                        _ = shutdown.changed() => return,
                    }
                }
            };
            if let Some(updated) = changed {
                match updated.sign(&keypair, Some(packet.timestamp())) {
                    Ok(new_packet) => {
                        records = updated;
                        packet = new_packet;
                        pending = true;
                        info!(
                            "DNS records changed in {path:?}; publishing {} records",
                            records.len()
                        );
                    }
                    Err(error) => error!("Cannot sign {path:?}: {error:#}"),
                }
                continue;
            }
        }
        tokio::select! {
            _ = ticker.tick() => {
                if let Some(updated) = read_updated_records(&path, &records) {
                    match updated.sign(&keypair, Some(packet.timestamp())) {
                        Ok(new_packet) => {
                            records = updated;
                            packet = new_packet;
                            pending = true;
                            info!("DNS records changed in {path:?}; publishing {} records", records.len());
                        }
                        Err(error) => error!("Cannot sign {path:?}: {error:#}"),
                    }
                }
            }
            _ = tokio::time::sleep_until(last_publish + republish_interval) => {}
            _ = shutdown.changed() => break,
        }
    }
}

fn read_updated_records(path: &Path, current: &DnsRecords) -> Option<DnsRecords> {
    match DnsRecords::load(path) {
        Ok(next) if next != *current => Some(next),
        Ok(_) => None,
        Err(error) => {
            warn!("Keeping the last valid DNS records: {error:#}");
            None
        }
    }
}

/// Resolve a conflict before re-signing: PKARR rejects any packet older than the newest
/// timestamp on a network. A finite retry bound avoids fighting another active writer forever.
async fn publish_local(
    keypair: &Keypair,
    networks: &[PkarrNetwork],
    cache: &PacketCache,
    records: &DnsRecords,
    packet: &mut SignedPacket,
) -> bool {
    for attempt in 0..3 {
        // Persist before publishing so a failed network request cannot lose the packet.
        if let Err(error) = cache.store(packet).await {
            warn!(
                "Cannot cache local PKARR packet in {:?}: {error:#}",
                cache.path()
            );
        }
        let results = join_all(
            networks
                .iter()
                .map(|network| publish_with_retries(network, packet, &RETRY_DELAYS)),
        )
        .await;
        let mut success = true;
        let mut conflict = false;
        for (network, result) in networks.iter().zip(results) {
            match result {
                PublishResult::Published => {
                    info!("Published local PKARR packet to {}", network.name)
                }
                PublishResult::NewerPacketExists => {
                    conflict = true;
                    success = false;
                    warn!("{} has a newer PKARR packet", network.name);
                }
                PublishResult::Failed(error) => {
                    success = false;
                    error!("Publishing to {} failed: {error}", network.name);
                }
            }
        }
        if !conflict {
            return success;
        }
        if attempt == 2 {
            break;
        }
        let newer = resolve_most_recent(&keypair.public_key(), networks).await;
        let previous = most_recent_packet(newer.packet(), Some(packet.clone()))
            .map(|(packet, _)| packet.timestamp());
        match records.sign(keypair, previous) {
            Ok(replacement) => *packet = replacement,
            Err(error) => {
                error!("Cannot re-sign local PKARR packet: {error:#}");
                break;
            }
        }
    }
    error!("Local PKARR packet was rejected repeatedly; another publisher may be using this key");
    false
}

async fn republish_periodically(
    public_key: PublicKey,
    networks: Vec<PkarrNetwork>,
    cache: PacketCache,
    republish_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        // Both awaits are raced against shutdown, so a run in progress (e.g. waiting for a
        // retry) is cancelled as well.
        tokio::select! {
            outcome = republish_once(&public_key, &networks, &cache, &RETRY_DELAYS) => {
                log_outcome(&public_key, &outcome);
            }
            _ = shutdown_rx.changed() => break,
        }
        tokio::select! {
            _ = tokio::time::sleep(republish_interval) => {}
            _ = shutdown_rx.changed() => break,
        }
    }
}

fn log_outcome(public_key: &PublicKey, outcome: &RepublishOutcome) {
    match outcome {
        RepublishOutcome::NotFound => warn!(
            "No PKARR packet found for {public_key}, neither on the networks nor in the cache. \
             Nothing to republish. Publish a packet with your external publishing tool. \
             To manage records locally, select local-records mode and run pubky-tls-proxy init."
        ),
        RepublishOutcome::ResolveFailed => error!(
            "Could not resolve the PKARR packet for {public_key} and none is cached. \
             Nothing republished. Check the network connection."
        ),
        RepublishOutcome::Republished {
            succeeded,
            have_newer_packet,
            ..
        } if succeeded.is_empty() && have_newer_packet.is_empty() => {
            error!("Republishing the PKARR packet for {public_key} failed on all networks");
        }
        RepublishOutcome::Republished { succeeded, .. } if succeeded.is_empty() => {
            info!("Nothing republished for {public_key}: the networks hold a newer packet");
        }
        RepublishOutcome::Republished {
            timestamp,
            source,
            succeeded,
            ..
        } => {
            let packet_age_secs =
                Timestamp::now().as_u64().saturating_sub(timestamp.as_u64()) / 1_000_000;
            let from = match source {
                PacketSource::Networks => "",
                PacketSource::Cache => " from the cache",
            };
            info!(
                "Republished PKARR packet for {public_key}{from} (signed {packet_age_secs}s ago) to: {}",
                succeeded.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mainline::Testnet;
    use pkarr::Keypair;
    use std::fs;
    use tempfile::TempDir;

    /// A local DHT, so tests don't need internet access.
    struct LocalDht {
        testnet: Testnet,
    }

    impl LocalDht {
        async fn start() -> Self {
            // Building a testnet blocks until all nodes are up.
            let testnet = tokio::task::spawn_blocking(|| Testnet::builder(5).build())
                .await
                .unwrap()
                .expect("local testnet starts");
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
            self.network().client.publish(packet).await.unwrap();
        }

        async fn resolve(&self, public_key: &PublicKey) -> SignedPacket {
            self.network()
                .client
                .resolve(public_key, ResolvePolicy::NetworkOnly)
                .await
                .unwrap()
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

    /// A packet cache in its own temporary directory.
    struct TestCache {
        _dir: TempDir,
        cache: PacketCache,
    }

    impl TestCache {
        fn empty(public_key: &PublicKey) -> Self {
            let dir = TempDir::new().unwrap();
            let cache = PacketCache::new(dir.path().join("pkarr-packet.cache"), public_key.clone());
            Self { _dir: dir, cache }
        }

        async fn holding(packet: &SignedPacket) -> Self {
            let test_cache = Self::empty(&packet.public_key());
            test_cache.cache.store(packet).await.unwrap();
            test_cache
        }

        async fn packet(&self) -> Option<SignedPacket> {
            self.cache.load().await
        }
    }

    #[tokio::test]
    async fn packet_from_the_networks_is_republished_unchanged_and_cached() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        dht.publish(&packet).await;
        let cache = TestCache::empty(&keypair.public_key());

        let outcome =
            republish_once(&keypair.public_key(), &[dht.network()], &cache.cache, &[]).await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                source: PacketSource::Networks,
                succeeded: vec!["DHT"],
                have_newer_packet: vec![],
                failed: vec![],
            }
        );
        let resolved = dht.resolve(&keypair.public_key()).await;
        assert_eq!(resolved.as_bytes(), packet.as_bytes());
        assert_eq!(cache.packet().await.unwrap().as_bytes(), packet.as_bytes());
    }

    #[tokio::test]
    async fn packet_missing_from_the_networks_is_republished_from_the_cache() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        let cache = TestCache::holding(&packet).await;

        let outcome =
            republish_once(&keypair.public_key(), &[dht.network()], &cache.cache, &[]).await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                source: PacketSource::Cache,
                succeeded: vec!["DHT"],
                have_newer_packet: vec![],
                failed: vec![],
            }
        );
        let resolved = dht.resolve(&keypair.public_key()).await;
        assert_eq!(resolved.as_bytes(), packet.as_bytes());
    }

    #[tokio::test]
    async fn newer_packet_on_the_networks_replaces_the_cached_one() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let older_packet = signed_packet_with_text(&keypair, "older");
        let newer_packet = signed_packet_with_text(&keypair, "newer");
        dht.publish(&newer_packet).await;
        let cache = TestCache::holding(&older_packet).await;

        let outcome =
            republish_once(&keypair.public_key(), &[dht.network()], &cache.cache, &[]).await;

        assert!(matches!(
            outcome,
            RepublishOutcome::Republished { timestamp, source: PacketSource::Networks, .. }
                if timestamp == newer_packet.timestamp()
        ));
        assert_eq!(
            cache.packet().await.unwrap().as_bytes(),
            newer_packet.as_bytes()
        );
    }

    #[tokio::test]
    async fn newer_cached_packet_is_republished_over_an_older_one_on_the_networks() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let older_packet = signed_packet_with_text(&keypair, "older");
        let newer_packet = signed_packet_with_text(&keypair, "newer");
        dht.publish(&older_packet).await;
        let cache = TestCache::holding(&newer_packet).await;

        let outcome =
            republish_once(&keypair.public_key(), &[dht.network()], &cache.cache, &[]).await;

        assert!(matches!(
            outcome,
            RepublishOutcome::Republished { timestamp, source: PacketSource::Cache, .. }
                if timestamp == newer_packet.timestamp()
        ));
        let resolved = dht.resolve(&keypair.public_key()).await;
        assert_eq!(resolved.as_bytes(), newer_packet.as_bytes());
    }

    #[tokio::test]
    async fn cached_packet_is_used_when_no_network_can_be_asked() {
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        let cache = TestCache::holding(&packet).await;

        let outcome = republish_once(
            &keypair.public_key(),
            &[unreachable_relay()],
            &cache.cache,
            &[],
        )
        .await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                source: PacketSource::Cache,
                succeeded: vec![],
                have_newer_packet: vec![],
                failed: vec!["relays"],
            }
        );
    }

    #[tokio::test]
    async fn unwritable_cache_does_not_stop_republishing() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        dht.publish(&packet).await;
        let cache = PacketCache::new(
            "/does/not/exist/pkarr-packet.cache".into(),
            keypair.public_key(),
        );

        let outcome = republish_once(&keypair.public_key(), &[dht.network()], &cache, &[]).await;

        assert!(matches!(
            outcome,
            RepublishOutcome::Republished { ref succeeded, .. } if succeeded == &["DHT"]
        ));
    }

    #[tokio::test]
    async fn unknown_public_key_without_cache_is_not_found() {
        let dht = LocalDht::start().await;
        let unknown_public_key = Keypair::random().public_key();
        let cache = TestCache::empty(&unknown_public_key);

        let outcome =
            republish_once(&unknown_public_key, &[dht.network()], &cache.cache, &[]).await;

        assert_eq!(outcome, RepublishOutcome::NotFound);
    }

    #[tokio::test]
    async fn unreachable_networks_without_cache_are_a_resolve_failure() {
        let public_key = Keypair::random().public_key();
        let cache = TestCache::empty(&public_key);

        let outcome = republish_once(&public_key, &[unreachable_relay()], &cache.cache, &[]).await;

        assert_eq!(outcome, RepublishOutcome::ResolveFailed);
    }

    #[tokio::test]
    async fn failing_network_does_not_prevent_publishing_to_the_others() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let packet = signed_packet(&keypair);
        dht.publish(&packet).await;
        let networks = [dht.network(), unreachable_relay()];
        let cache = TestCache::empty(&keypair.public_key());

        let outcome = republish_once(
            &keypair.public_key(),
            &networks,
            &cache.cache,
            &[Duration::from_millis(10)],
        )
        .await;

        assert_eq!(
            outcome,
            RepublishOutcome::Republished {
                timestamp: packet.timestamp(),
                source: PacketSource::Networks,
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

        assert!(matches!(result, PublishResult::NewerPacketExists));
    }

    #[tokio::test]
    async fn local_file_publishes_new_records_and_removes_deleted_records() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-records.toml");
        fs::write(&path, "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'\n[[records]]\nname='_old'\ntype='TXT'\ntext='old'").unwrap();
        let records = DnsRecords::load(&path).unwrap();
        let cache = PacketCache::new(dir.path().join("cache"), keypair.public_key());
        let publisher = PkarrPublisher::start_local_records(
            keypair.clone(),
            vec![dht.network()],
            cache,
            Duration::from_secs(3600),
            path.clone(),
            records,
        );
        let first = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(packet) = dht
                    .network()
                    .client
                    .resolve(&keypair.public_key(), ResolvePolicy::NetworkOnly)
                    .await
                {
                    if packet.all_resource_records().count() == 2 {
                        break packet;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();

        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.11'",
        )
        .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(packet) = dht
                    .network()
                    .client
                    .resolve(&keypair.public_key(), ResolvePolicy::NetworkOnly)
                    .await
                {
                    if packet.timestamp() > first.timestamp()
                        && packet.all_resource_records().count() == 1
                    {
                        break packet;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(second.all_resource_records().count(), 1);
        publisher.shutdown(None).await.unwrap();
    }

    #[tokio::test]
    async fn local_records_override_a_newer_external_packet() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-records.toml");
        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'",
        )
        .unwrap();
        let records = DnsRecords::load(&path).unwrap();
        let newer = SignedPacket::builder()
            .txt(
                "_other".try_into().unwrap(),
                "external".try_into().unwrap(),
                300,
            )
            .timestamp(Timestamp::from(
                (Timestamp::now().as_u64() + 1_000_000).to_be_bytes(),
            ))
            .sign(&keypair)
            .unwrap();
        dht.publish(&newer).await;
        let cache = PacketCache::new(dir.path().join("cache"), keypair.public_key());
        let mut packet = records.sign(&keypair, None).unwrap();
        assert!(publish_local(&keypair, &[dht.network()], &cache, &records, &mut packet).await);
        let resolved = dht.resolve(&keypair.public_key()).await;
        assert!(resolved.timestamp() > newer.timestamp());
        assert_eq!(resolved.all_resource_records().count(), 1);
    }

    #[tokio::test]
    async fn invalid_live_edit_keeps_last_valid_packet_until_corrected() {
        let dht = LocalDht::start().await;
        let keypair = Keypair::random();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-records.toml");
        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'",
        )
        .unwrap();
        let records = DnsRecords::load(&path).unwrap();
        let cache = PacketCache::new(dir.path().join("cache"), keypair.public_key());
        let publisher = PkarrPublisher::start_local_records(
            keypair.clone(),
            vec![dht.network()],
            cache,
            Duration::from_secs(3600),
            path.clone(),
            records,
        );
        let original = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(packet) = dht
                    .network()
                    .client
                    .resolve(&keypair.public_key(), ResolvePolicy::NetworkOnly)
                    .await
                {
                    break packet;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();
        fs::write(&path, "[[records]]\nname='@'\ntype='A'\naddress='invalid'").unwrap();
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(
            dht.resolve(&keypair.public_key()).await.as_bytes(),
            original.as_bytes()
        );
        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.11'",
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if dht.resolve(&keypair.public_key()).await.timestamp() > original.timestamp() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();
        publisher.shutdown(None).await.unwrap();
    }

    #[tokio::test]
    async fn edit_cancels_network_retry_and_caches_the_new_packet() {
        let keypair = Keypair::random();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-records.toml");
        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'",
        )
        .unwrap();
        let records = DnsRecords::load(&path).unwrap();
        let cache = PacketCache::new(dir.path().join("cache"), keypair.public_key());
        let publisher = PkarrPublisher::start_local_records(
            keypair.clone(),
            vec![unreachable_relay()],
            cache,
            Duration::from_secs(3600),
            path.clone(),
            records,
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        fs::write(
            &path,
            "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.11'",
        )
        .unwrap();
        let cache = PacketCache::new(dir.path().join("cache"), keypair.public_key());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(packet) = cache.load().await {
                    if matches!(packet.all_resource_records().next().map(|r| &r.rdata),
                        Some(pkarr::dns::rdata::RData::A(a)) if a.address == u32::from("203.0.113.11".parse::<std::net::Ipv4Addr>().unwrap())) { break; }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.unwrap();
        publisher.shutdown(None).await.unwrap();
    }
}
