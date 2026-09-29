//! Validate the real executable's offline check and startup error behavior.

use std::{fs, process::Command};

#[test]
fn check_validates_records_without_creating_a_secret_or_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let records = dir.path().join("dns-records.toml");
    fs::write(
        &config,
        "secret_file = 'secret'\nlisten_addrs = ['127.0.0.1:0']\n",
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
