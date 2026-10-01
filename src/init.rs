//! Prepare starter files without prompts or publication. Review the detected
//! address and backend settings before normal startup publishes the records.

use anyhow::{ensure, Context, Result};
use clap::Args;
use std::{
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::NamedTempFile;

/// Optional overrides for starter files. Initialization never requires a terminal.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Directory containing config.toml. Defaults to ~/.pubky-tls-proxy.
    #[arg(long)]
    pub directory: Option<PathBuf>,
    /// Public IPv4 for the generated A record. Skips address detection.
    #[arg(long)]
    pub public_ip: Option<Ipv4Addr>,
    /// Public TLS port advertised in the generated HTTPS record.
    #[arg(long, default_value_t = 8443, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
}

/// Create missing starter files. Never starts listeners or publishes.
/// Invalid existing files or failed address detection fail before writing.
pub async fn run(args: &InitArgs) -> Result<()> {
    let directory = match &args.directory {
        Some(path) => path.clone(),
        None => std::env::home_dir()
            .context("Cannot locate home directory; use --directory")?
            .join(".pubky-tls-proxy"),
    };
    let config_path = directory.join("config.toml");
    let settings = crate::config::init_settings(&config_path)?;
    let secret_path = &settings.secret_key_file;
    let records_path = settings.dns_records_file.as_deref();
    let existing_key = crate::secret::check_keypair(secret_path)?;
    let secret_existed = existing_key.is_some();
    let existing_records = match records_path {
        Some(path) if path_exists(path)? => Some(crate::dns_records::DnsRecords::load(path)?),
        _ => None,
    };
    if let Some(records) = &existing_records {
        records.sign(
            &existing_key.clone().unwrap_or_else(pkarr::Keypair::random),
            None,
        )?;
    }
    let prepared_records = if records_path.is_some() && existing_records.is_none() {
        Some(prepare_records(args).await?)
    } else {
        None
    };

    if let (Some(records), Some(path)) = (&prepared_records, records_path) {
        crate::dns_records::DnsRecords::parse(&records.contents, path)?
            .sign(&existing_key.unwrap_or_else(pkarr::Keypair::random), None)?;
    }
    let config_created =
        create_file_if_missing(&config_path, include_str!("../config.example.toml"))?;
    let keypair = crate::secret::load_or_create_keypair(secret_path)?;
    let mut records_created = false;
    if let (Some(records), Some(path)) = (&prepared_records, records_path) {
        records_created = create_file_if_missing(path, &records.contents)?;
    }
    if let Some(path) = records_path {
        crate::dns_records::DnsRecords::load(path)?.sign(&keypair, None)?;
    }
    println!("\nSetup complete. Nothing has been published.");
    println!("\nFiles in {}:", directory.display());
    print_file(&directory, &config_path, "Proxy settings", !config_created);
    if let Some(path) = records_path {
        let description = match &prepared_records {
            Some(records) if records_created => {
                format!("Public IP: {} · Port: {}", records.address, records.port)
            }
            _ => "DNS records".to_owned(),
        };
        print_file(&directory, path, &description, !records_created);
    }
    print_file(
        &directory,
        secret_path,
        "Your identity key — keep and back up",
        secret_existed,
    );
    print_next_steps(&config_path, &settings, args.directory.is_some());
    Ok(())
}

/// The detected or supplied endpoint and its complete starter DNS records file.
struct PreparedRecords {
    address: Ipv4Addr,
    port: u16,
    contents: String,
}

async fn prepare_records(args: &InitArgs) -> Result<PreparedRecords> {
    let address = match args.public_ip {
        Some(ip) => {
            validate_public_ipv4(ip)?;
            ip
        }
        None => {
            println!("Looking up your public IPv4...");
            detect_public_ipv4().await.context(
                "Could not detect public IPv4. Rerun init with --public-ip YOUR_PUBLIC_IPV4.",
            )?
        }
    };
    Ok(PreparedRecords {
        address,
        port: args.port,
        contents: starter_records(address, args.port),
    })
}

fn print_file(directory: &Path, path: &Path, description: &str, kept_existing: bool) {
    let name = path.strip_prefix(directory).unwrap_or(path);
    let status = if kept_existing {
        " (kept existing)"
    } else {
        ""
    };
    println!("  {:<18} {description}{status}", name.display());
}

fn print_next_steps(
    config_path: &Path,
    settings: &crate::config::InitSettings,
    custom_directory: bool,
) {
    let directory = config_path.parent().unwrap_or(Path::new("."));
    let config_name = config_path.strip_prefix(directory).unwrap_or(config_path);
    println!("\nBefore starting:");
    println!(
        "  1. Open {} and set http_backend_addr to your HTTP service.",
        config_name.display()
    );
    println!("     Current: {}", settings.http_backend_addr);
    if let Some(path) = &settings.dns_records_file {
        let name = path.strip_prefix(directory).unwrap_or(path);
        println!("\n  2. Check the IP and port in {}.", name.display());
        println!("     Clients must be able to reach this address and port.");
    }
    let config_arg = if custom_directory {
        format!(" --config {config_path:?}")
    } else {
        String::new()
    };
    println!("\nThen validate and start:\n  pubky-tls-proxy{config_arg} --check\n  pubky-tls-proxy{config_arg}");
    match settings.pkarr_mode {
        Some(crate::config::PkarrMode::LocalRecords) => {
            println!("\nStarting the proxy publishes your DNS records.")
        }
        Some(crate::config::PkarrMode::ExternalPacket) => {
            println!("\nStarting the proxy republishes your externally managed DNS packet.")
        }
        None => println!("\nStarting the proxy runs with publishing disabled."),
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Cannot inspect {}", path.display())),
    }
}

/// Persist complete contents without replacing any existing path, including symlinks.
/// Returns true only when this call created the file.
fn create_file_if_missing(path: &Path, contents: &str) -> Result<bool> {
    if path_exists(path)? {
        return Ok(false);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(contents.as_bytes())?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(true),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Cannot create {}", path.display())),
    }
}

fn starter_records(ip: Ipv4Addr, port: u16) -> String {
    format!(
        r#"# Review the public address before starting the proxy. IP changes require editing this file.
default_ttl = 300

[[records]]
name = "@"
type = "A"
address = "{ip}"

[[records]]
name = "@"
type = "HTTPS"
priority = 1
target = "."
# Public port clients connect to. Use 443 for a shared-port setup.
port = {port}
"#
    )
}

fn parse_public_ipv4(text: &str) -> Result<Ipv4Addr> {
    let ip = text
        .trim()
        .parse()
        .context("Expected a valid public IPv4 address")?;
    validate_public_ipv4(ip)?;
    Ok(ip)
}

fn validate_public_ipv4(ip: Ipv4Addr) -> Result<()> {
    // Special-purpose ranges not covered by the stable standard-library predicates.
    let special_purpose = match ip.octets() {
        [0, ..] | [224..=255, ..] => true, // This network, multicast, reserved.
        [100, 64..=127, ..] => true,       // Shared address space (CGNAT).
        [198, 18..=19, ..] => true,        // Benchmarking.
        [192, 0, 0, 9 | 10] => false,      // Globally reachable anycast exceptions.
        [192, 0, 0, _] => true,            // IETF protocol assignments.
        [192, 88, 99, _] => true,          // Deprecated 6to4 relay space.
        _ => false,
    };
    ensure!(
        !(ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_documentation()
            || special_purpose),
        "{ip} is not a globally routable public IPv4 address"
    );
    Ok(())
}

async fn detect_public_ipv4() -> Result<Ipv4Addr> {
    let client = reqwest::Client::builder()
        .local_address(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()?;
    tokio::time::timeout(
        Duration::from_secs(6),
        detect_from_services(
            &client,
            &["https://api.ipify.org", "https://ipv4.icanhazip.com"],
        ),
    )
    .await
    .context("Public IP detection timed out")?
}

async fn detect_from_services(client: &reqwest::Client, urls: &[&str]) -> Result<Ipv4Addr> {
    let mut last_error = None;
    for url in urls {
        match fetch_public_ipv4(client, url).await {
            Ok(ip) => return Ok(ip),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No IP detection services configured")))
}

async fn fetch_public_ipv4(client: &reqwest::Client, url: &str) -> Result<Ipv4Addr> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    ensure!(
        response.status().is_success(),
        "IP service returned {}",
        response.status()
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= 64,
            "IP service response exceeded 64 bytes"
        );
        body.extend_from_slice(&chunk);
    }
    parse_public_ipv4(std::str::from_utf8(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn service(body: &'static str, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            tokio::time::sleep(delay).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        url
    }

    #[tokio::test]
    async fn detection_falls_back_after_invalid_response_or_timeout() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        for (body, delay) in [
            ("not an IP", Duration::ZERO),
            ("8.8.8.8", Duration::from_secs(1)),
        ] {
            let first = service(body, delay).await;
            let second = service("1.1.1.1\n", Duration::ZERO).await;
            assert_eq!(
                detect_from_services(&client, &[&first, &second])
                    .await
                    .unwrap(),
                Ipv4Addr::new(1, 1, 1, 1)
            );
        }
    }

    #[tokio::test]
    async fn detection_rejects_private_addresses_and_oversized_responses() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for body in [
            "192.168.1.1",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            let url = service(body, Duration::ZERO).await;
            assert!(fetch_public_ipv4(&client, &url).await.is_err());
        }
    }

    #[test]
    fn public_ip_validation_rejects_non_global_ranges() {
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "172.16.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(parse_public_ipv4(ip).is_err(), "{ip}");
        }
        assert_eq!(
            parse_public_ipv4("8.8.8.8\n").unwrap(),
            Ipv4Addr::new(8, 8, 8, 8)
        );
    }
}
