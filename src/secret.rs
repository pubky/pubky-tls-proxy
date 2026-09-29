//! Persistent proxy identity, generated only when the secret file is absent.

use anyhow::{Context, Result};
use pkarr::Keypair;
use std::{
    fs,
    io::{ErrorKind, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use tracing::info;

/// Loads a hex secret or saves a new one before returning its keypair.
/// Existing files, including invalid ones, are never overwritten.
pub fn load_or_create_keypair(path: &Path) -> Result<Keypair> {
    match fs::symlink_metadata(path) {
        Ok(_) => return read_keypair(path),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to inspect secret file: {path:?}"))
        }
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create secret directory: {parent:?}"))?;
    let keypair = Keypair::random();
    // Temp files have owner-only permissions on Unix. Publish the complete secret
    // without replacing a file another process may have created in the meantime.
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to create temporary secret in {parent:?}"))?;
    writeln!(temporary, "{}", hex::encode(keypair.secret_key()))
        .context("Failed to write secret key")?;
    temporary
        .as_file()
        .sync_all()
        .context("Failed to sync secret key")?;
    match temporary.persist_noclobber(path) {
        Ok(_) => {
            info!("Generated secret file at {path:?}");
            Ok(keypair)
        }
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => read_keypair(path),
        Err(error) => Err(error).with_context(|| format!("Failed to save secret file: {path:?}")),
    }
}

/// Validates an existing identity without creating one. Only an absent path is allowed
/// for first-time setup; unreadable files and dangling symlinks remain errors.
pub fn check_keypair(path: &Path) -> Result<Option<Keypair>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_keypair(path).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to inspect secret file: {path:?}"))
        }
    }
}

fn read_keypair(path: &Path) -> Result<Keypair> {
    info!("Loading secret file from {path:?}");
    let secret_hex = fs::read_to_string(path)
        .with_context(|| format!("Failed to read secret file: {path:?}"))?;
    let secret_bytes = hex::decode(secret_hex.trim()).context("Failed to decode hex secret key")?;
    let secret_key: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Secret key must be exactly 32 bytes (64 hex chars)"))?;
    Ok(Keypair::from_secret_key(&secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_parent_directories_and_reuses_saved_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/custom.hex");
        let first = load_or_create_keypair(&path).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(hex::decode(contents.trim()).unwrap().len(), 32);
        assert_eq!(
            load_or_create_keypair(&path).unwrap().public_key(),
            first.public_key()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn existing_invalid_secrets_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        for contents in ["", "invalid hex", "abcd"] {
            fs::write(&path, contents).unwrap();
            assert!(load_or_create_keypair(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        }
    }

    #[test]
    fn concurrent_starts_use_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        load_or_create_keypair(&path).unwrap().public_key()
                    })
                })
                .collect();
            let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(keys.iter().all(|key| key == &keys[0]));
        });
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_not_replaced_or_followed_for_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let target = dir.path().join("missing");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(load_or_create_keypair(&path).is_err());
        assert_eq!(fs::read_link(&path).unwrap(), target);
        assert!(!target.exists());
    }
}
