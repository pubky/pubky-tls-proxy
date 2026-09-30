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
fn check_validates_records_without_creating_a_secret_or_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let records = dir.path().join("dns-records.toml");
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
    assert!(!dir.path().join("secret").exists());
    assert!(!dir.path().join("pkarr-packet.cache").exists());

    fs::write(
        &records,
        "[[records]]\nname='@'\ntype='A'\naddress='not-an-ip'\n",
    )
    .unwrap();
    let invalid = check();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("record 1"));
    assert!(!dir.path().join("secret").exists());
}

#[test]
fn check_validates_explicit_records_when_publishing_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let records = dir.path().join("custom-records.toml");
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
        for (address, valid) in [("203.0.113.10", true), ("not-an-ip", false)] {
            fs::write(
                &records,
                format!("[[records]]\nname='@'\ntype='A'\naddress='{address}'\n"),
            )
            .unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"));
            command.arg("--config").arg(&config).arg("--check");
            if disable_via_cli {
                command.arg("--no-pkarr-publish");
            }
            let result = command.output().unwrap();
            assert_eq!(
                result.status.success(),
                valid,
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            if !valid {
                assert!(String::from_utf8_lossy(&result.stderr).contains("record 1"));
            }
            assert!(!dir.path().join("custom-key").exists());
            assert!(!dir.path().join("custom.cache").exists());
        }
    }
}
