//! A copy of the PKARR packet on disk.
//!
//! If an externally managed packet disappears from the DHT and relays, the republisher
//! can publish the cached copy. For locally managed records the cache tracks the latest
//! signed timestamp, while the records file remains authoritative.
//!
//! The file holds one PKARR packet in the `pkarr` crate's [`SignedPacket::serialize`] format.

use anyhow::{bail, ensure, Context, Result};
use pkarr::{PublicKey, SignedPacket};
use std::{
    io,
    path::{Path, PathBuf},
};
use tracing::warn;

/// `SignedPacket::serialize` writes 8 bytes `last_seen`, then the packet: 32 bytes public
/// key, 64 bytes signature, 8 bytes timestamp and the DNS packet.
const MIN_CACHE_FILE_BYTES: usize = 8 + 32 + 64 + 8;

/// The cache file for the packet of one public key.
pub struct PacketCache {
    path: PathBuf,
    public_key: PublicKey,
}

impl PacketCache {
    pub fn new(path: PathBuf, public_key: PublicKey) -> Self {
        Self { path, public_key }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the cached packet.
    ///
    /// Returns `None` if there is no cache file yet, or if the file can't be used: it's
    /// unreadable, corrupt, for another public key, or not validly signed. Unusable files
    /// are logged and left in place, so they can be inspected.
    pub async fn load(&self) -> Option<SignedPacket> {
        let bytes = match tokio::fs::read(&self.path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
            Err(error) => {
                warn!(
                    "Can't read the cached PKARR packet {:?}: {error}",
                    self.path
                );
                return None;
            }
        };

        match parse_cached_packet(&bytes, &self.public_key) {
            Ok(packet) => Some(packet),
            Err(error) => {
                warn!(
                    "Ignoring the cached PKARR packet {:?}: {error:#}",
                    self.path
                );
                None
            }
        }
    }

    /// Replaces the cached packet with `packet`.
    ///
    /// Writes to a temporary file first and then renames it, so the cache file is never
    /// left half-written.
    pub async fn store(&self, packet: &SignedPacket) -> io::Result<()> {
        let mut temporary_path = self.path.clone().into_os_string();
        temporary_path.push(".tmp");

        tokio::fs::write(&temporary_path, packet.serialize()).await?;
        tokio::fs::rename(&temporary_path, &self.path).await
    }
}

fn parse_cached_packet(bytes: &[u8], expected_public_key: &PublicKey) -> Result<SignedPacket> {
    // `SignedPacket::deserialize` panics on files shorter than 8 bytes.
    ensure!(
        bytes.len() >= MIN_CACHE_FILE_BYTES,
        "the file is too short to hold a packet ({} bytes)",
        bytes.len()
    );

    let packet =
        SignedPacket::deserialize(bytes).context("the file doesn't hold a PKARR packet")?;
    if packet.public_key() != *expected_public_key {
        bail!(
            "the packet belongs to another public key: {}",
            packet.public_key()
        );
    }

    // `SignedPacket::deserialize` doesn't check the signature, `from_relay_payload` does.
    SignedPacket::from_relay_payload(expected_public_key, &packet.to_relay_payload())
        .context("the packet's signature is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::Keypair;
    use tempfile::TempDir;

    struct CacheDir {
        dir: TempDir,
    }

    impl CacheDir {
        fn new() -> Self {
            Self {
                dir: TempDir::new().unwrap(),
            }
        }

        fn cache_file(&self) -> PathBuf {
            self.dir.path().join("pkarr-packet.cache")
        }

        fn cache_for(&self, keypair: &Keypair) -> PacketCache {
            PacketCache::new(self.cache_file(), keypair.public_key())
        }
    }

    fn signed_packet(keypair: &Keypair) -> SignedPacket {
        SignedPacket::builder()
            .txt(
                "_demo".try_into().unwrap(),
                "hello".try_into().unwrap(),
                300,
            )
            .sign(keypair)
            .unwrap()
    }

    #[tokio::test]
    async fn stored_packet_is_loaded_unchanged() {
        let dir = CacheDir::new();
        let keypair = Keypair::random();
        let cache = dir.cache_for(&keypair);
        let packet = signed_packet(&keypair);

        cache.store(&packet).await.unwrap();
        let loaded = cache.load().await.unwrap();

        assert_eq!(loaded.as_bytes(), packet.as_bytes());
    }

    #[tokio::test]
    async fn storing_replaces_the_previous_packet() {
        let dir = CacheDir::new();
        let keypair = Keypair::random();
        let cache = dir.cache_for(&keypair);
        let older_packet = signed_packet(&keypair);
        let newer_packet = signed_packet(&keypair);

        cache.store(&older_packet).await.unwrap();
        cache.store(&newer_packet).await.unwrap();

        assert_eq!(
            cache.load().await.unwrap().as_bytes(),
            newer_packet.as_bytes()
        );
    }

    #[tokio::test]
    async fn missing_file_is_an_empty_cache() {
        let dir = CacheDir::new();

        assert!(dir.cache_for(&Keypair::random()).load().await.is_none());
    }

    #[tokio::test]
    async fn too_short_file_is_ignored() {
        let dir = CacheDir::new();
        std::fs::write(dir.cache_file(), b"short").unwrap();

        assert!(dir.cache_for(&Keypair::random()).load().await.is_none());
    }

    #[tokio::test]
    async fn corrupt_file_is_ignored() {
        let dir = CacheDir::new();
        std::fs::write(dir.cache_file(), [0xAB; 300]).unwrap();

        assert!(dir.cache_for(&Keypair::random()).load().await.is_none());
    }

    #[tokio::test]
    async fn packet_of_another_public_key_is_ignored() {
        let dir = CacheDir::new();
        let other_keypair = Keypair::random();
        dir.cache_for(&other_keypair)
            .store(&signed_packet(&other_keypair))
            .await
            .unwrap();

        assert!(dir.cache_for(&Keypair::random()).load().await.is_none());
    }

    #[tokio::test]
    async fn packet_with_invalid_signature_is_ignored() {
        let dir = CacheDir::new();
        let keypair = Keypair::random();
        let mut bytes = signed_packet(&keypair).serialize();
        // Flip a bit in the signature, which follows last_seen (8) and the public key (32).
        bytes[8 + 32] ^= 1;
        std::fs::write(dir.cache_file(), bytes).unwrap();

        assert!(dir.cache_for(&keypair).load().await.is_none());
    }
}
