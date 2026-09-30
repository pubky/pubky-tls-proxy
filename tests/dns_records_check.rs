//! Validate the real executable's offline check and startup error behavior.

use std::{fs, process::Command};

#[test]
fn check_rejects_invalid_saved_secrets_and_preserves_valid_ones() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let secret = dir.path().join("secret");
    fs::write(&config, "[pkarr]\npublish=false\n").unwrap();
    for (contents, valid) in [("bad key".to_string(), false), ("01".repeat(32), true)] {
        fs::write(&secret, &contents).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
            .arg("--config")
            .arg(&config)
            .arg("--check")
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            valid,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_to_string(&secret).unwrap(), contents);
    }
}

#[test]
fn check_validates_records_without_modifying_secret_or_creating_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let records = dir.path().join("dns-records.toml");
    fs::write(dir.path().join("secret"), "01".repeat(32)).unwrap();
    fs::write(
        &config,
        "secret_key_file = 'secret'\nlisten_addrs = ['127.0.0.1:0']\n",
    )
    .unwrap();
    fs::write(
        &records,
        "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'\n",
    )
    .unwrap();

    let check = || {
        Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
            .arg("--config")
            .arg(&config)
            .arg("--check")
            .output()
            .unwrap()
    };
    let valid = check();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("secret")).unwrap(),
        "01".repeat(32)
    );
    assert!(!dir.path().join("pkarr-packet.cache").exists());

    fs::write(
        &records,
        "[[records]]\nname='@'\ntype='A'\naddress='not-an-ip'\n",
    )
    .unwrap();
    let invalid = check();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("record 1"));
    assert_eq!(
        fs::read_to_string(dir.path().join("secret")).unwrap(),
        "01".repeat(32)
    );
}

#[test]
fn disabled_publishing_check_does_not_require_records() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(dir.path().join("custom-key"), "01".repeat(32)).unwrap();
    for disable_via_cli in [false, true] {
        fs::write(
            &config,
            format!(
                "secret_key_file = 'custom-key'\n\
                 [pkarr]\npublish = {disable_via_cli}\n\
                 dns_records_file = 'custom-records.toml'\n\
                 packet_cache_file = 'custom.cache'\n\
                 dht_bootstrap_nodes = []\nrelay_urls = []\n"
            ),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"));
        command.arg("--config").arg(&config).arg("--check");
        if disable_via_cli {
            command.arg("--no-pkarr-publish");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!dir.path().join("custom-records.toml").exists());
        assert!(!dir.path().join("custom.cache").exists());
    }
}

#[test]
fn startup_and_check_fail_on_missing_required_files_without_creating_them() {
    for missing in ["config.toml", "secret", "dns-records.toml"] {
        for check in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("config.toml");
            if missing != "config.toml" {
                fs::write(
                    &config,
                    "listen_addrs = ['127.0.0.1:0']\n[pkarr]\ndht_bootstrap_nodes = []\n",
                )
                .unwrap();
            }
            if missing != "secret" {
                fs::write(dir.path().join("secret"), "01".repeat(32)).unwrap();
            }
            if missing != "dns-records.toml" {
                fs::write(
                    dir.path().join("dns-records.toml"),
                    "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'\n",
                )
                .unwrap();
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"));
            command.arg("--config").arg(&config);
            if check {
                command.arg("--check");
            }
            let result = command.output().unwrap();
            assert!(!result.status.success());
            let error = String::from_utf8_lossy(&result.stderr);
            assert!(error.contains(missing), "{error}");
            assert!(error.contains("init --directory"), "{error}");
            assert!(!dir.path().join(missing).exists());
            assert!(!dir.path().join("pkarr-packet.cache").exists());
            assert!(!String::from_utf8_lossy(&result.stdout).contains("Listening on"));
        }
    }
}

#[test]
fn external_packet_check_requires_a_key_but_not_records() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, "[pkarr]\nmode = 'external-packet'\n").unwrap();
    fs::write(dir.path().join("secret"), "01".repeat(32)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
        .arg("--config")
        .arg(config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!dir.path().join("dns-records.toml").exists());
    assert!(!dir.path().join("pkarr-packet.cache").exists());
}
