//! Exercise setup through the executable without contacting public services.

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn init(directory: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
        .arg("init")
        .arg("--directory")
        .arg(directory)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn creates_starter_files_without_a_terminal_or_publication_and_preserves_them() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("setup");
    let result = init(&directory, &["--public-ip", "8.8.8.8"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("Nothing has been published"));
    let files: Vec<_> = ["config.toml", "secret", "dns-records.toml"]
        .into_iter()
        .map(|name| {
            (
                directory.join(name),
                fs::read(directory.join(name)).unwrap(),
            )
        })
        .collect();
    let records = fs::read_to_string(directory.join("dns-records.toml")).unwrap();
    assert!(records.contains("address = \"8.8.8.8\""));
    assert!(records.contains("port = 8443"));
    assert!(!directory.join("pkarr-packet.cache").exists());
    let repeated = init(&directory, &[]);
    assert!(
        repeated.status.success(),
        "{}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    for (path, contents) in files {
        assert_eq!(fs::read(path).unwrap(), contents);
    }
    let check = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
        .arg("--config")
        .arg(directory.join("config.toml"))
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn invalid_inputs_do_not_create_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("setup");
    for args in [
        &["--public-ip", "192.168.1.1"][..],
        &["--public-ip", "8.8.8.8", "--port", "0"],
    ] {
        assert!(!init(&directory, args).status.success());
        assert!(!directory.exists());
    }
}

#[test]
fn partial_setup_respects_existing_config_paths_and_secret() {
    let dir = tempfile::tempdir().unwrap();
    let config = "secret_key_file = 'saved.hex'\n[pkarr]\ndns_records_file = 'dns/custom.toml'\n";
    fs::write(dir.path().join("config.toml"), config).unwrap();
    let secret = "01".repeat(32);
    fs::write(dir.path().join("saved.hex"), &secret).unwrap();
    let result = init(dir.path(), &["--public-ip", "1.1.1.1", "--port", "443"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("saved.hex")).unwrap(),
        secret
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("config.toml")).unwrap(),
        config
    );
    assert!(fs::read_to_string(dir.path().join("dns/custom.toml"))
        .unwrap()
        .contains("port = 443"));
    assert!(!dir.path().join("dns-records.toml").exists());
}

#[test]
fn invalid_existing_files_are_preserved_without_creating_other_files() {
    for name in ["config.toml", "secret", "dns-records.toml"] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(name), "invalid").unwrap();
        assert!(!init(dir.path(), &["--public-ip", "8.8.8.8"])
            .status
            .success());
        assert_eq!(
            fs::read_to_string(dir.path().join(name)).unwrap(),
            "invalid"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn dangling_records_symlink_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("missing");
    let path = dir.path().join("dns-records.toml");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(!init(dir.path(), &["--public-ip", "8.8.8.8"])
        .status
        .success());
    assert_eq!(fs::read_link(path).unwrap(), target);
    assert!(!target.exists());
}

#[test]
fn invalid_config_settings_fail_before_creating_missing_files() {
    for config in [
        "listen_addrs = []\n",
        "[pkarr]\nrepublish_interval_secs = 0\n",
        "[pkarr]\nrelay_urls = ['not-a-url']\n",
        "[pkarr]\ndht_bootstrap_nodes = []\nrelay_urls = []\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), config).unwrap();
        assert!(!init(dir.path(), &["--public-ip", "8.8.8.8"])
            .status
            .success());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn concurrent_setup_keeps_complete_files_and_a_single_identity() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("setup");
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| init(&directory, &["--public-ip", "8.8.8.8"])))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut domains = Vec::new();
    for result in results {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        domains.push(
            String::from_utf8(result.stdout)
                .unwrap()
                .lines()
                .find(|line| line.starts_with("Public Key Domain:"))
                .unwrap()
                .to_owned(),
        );
    }
    assert!(domains.iter().all(|domain| domain == &domains[0]));
    assert_eq!(fs::read_dir(directory).unwrap().count(), 3);
}

#[test]
fn init_skips_local_records_for_external_mode_or_disabled_publishing() {
    for config in [
        "[pkarr]\nmode = 'external-packet'\n",
        "[pkarr]\npublish = false\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), config).unwrap();
        let result = init(dir.path(), &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(dir.path().join("secret").is_file());
        assert!(!dir.path().join("dns-records.toml").exists());
        assert_eq!(
            fs::read_to_string(dir.path().join("config.toml")).unwrap(),
            config
        );
        let check = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
            .arg("--config")
            .arg(dir.path().join("config.toml"))
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}
