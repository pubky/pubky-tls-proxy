//! Exercise Unix signals against the executable, without signalling the test runner.
#![cfg(unix)]

use anyhow::{Context, Result};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    time::timeout,
};

#[tokio::test]
async fn sigint_runs_application_shutdown() -> Result<()> {
    assert_signal_runs_shutdown("-INT").await
}

#[tokio::test]
async fn sigterm_runs_application_shutdown() -> Result<()> {
    assert_signal_runs_shutdown("-TERM").await
}

async fn assert_signal_runs_shutdown(signal: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("config.toml");
    std::fs::write(directory.path().join("secret"), "01".repeat(32))?;
    std::fs::write(
        &config,
        "secret_file = 'secret'\nlisten_addrs = ['127.0.0.1:0']\n[republish]\nenabled = false\n",
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_pubky-tls-proxy"))
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().context("Missing child stdout")?);

    // Waiting for the registered handlers avoids racing startup with signal delivery.
    timeout(Duration::from_secs(10), async {
        loop {
            let mut line = String::new();
            anyhow::ensure!(
                output.read_line(&mut line).await? > 0,
                "Proxy exited before readiness"
            );
            if line.contains("Press Ctrl+C to stop the proxy") {
                return anyhow::Ok(());
            }
        }
    })
    .await
    .context("Proxy did not become ready")??;

    let pid = child
        .id()
        .context("Proxy exited before receiving the signal")?;
    let sent = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .await?;
    anyhow::ensure!(sent.success(), "Could not send {signal}");

    let status = timeout(Duration::from_secs(10), child.wait())
        .await
        .context("Proxy did not shut down")??;
    let mut shutdown_log = String::new();
    output.read_to_string(&mut shutdown_log).await?;
    assert!(status.success(), "{signal}: {status}; {shutdown_log}");
    assert!(
        shutdown_log.contains("Received shutdown signal"),
        "{shutdown_log}"
    );
    assert!(
        shutdown_log.contains("Shutdown complete."),
        "{shutdown_log}"
    );
    Ok(())
}
