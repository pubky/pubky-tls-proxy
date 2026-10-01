//! Explicit publication preparation. Detection only suggests an address;
//! files are created after review and no PKARR network is contacted.

use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use std::{
    fs,
    io::{self, IsTerminal, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::NamedTempFile;

/// Inputs for interactive setup or a reproducible unattended installation.
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
    /// Create missing files without prompts. Requires --public-ip if records are missing.
    #[arg(long)]
    pub non_interactive: bool,
}

/// Review setup inputs and create missing files. Never starts listeners or publishes.
/// Invalid existing files and non-interactive incomplete inputs fail before writing.
pub async fn run(args: &InitArgs) -> Result<()> {
    let directory = match &args.directory {
        Some(path) => path.clone(),
        None => std::env::home_dir()
            .context("Cannot locate home directory; use --directory")?
            .join(".pubky-tls-proxy"),
    };
    let config_path = directory.join("config.toml");
    let paths = crate::config::init_file_paths(&config_path)?;
    let secret_path = paths.secret_key_file;
    let records_path = paths.dns_records_file;
    let interactive = !args.non_interactive;
    if interactive {
        ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "No interactive terminal; use --non-interactive and --public-ip"
        );
        println!("Pubky TLS Proxy setup\n");
        let files = if records_path.is_some() {
            "config, key, and DNS records"
        } else {
            "config and key"
        };
        println!("Prepare {files} in:\n  {}\n", directory.display());
        println!("Existing files are preserved. Nothing is started or published.");
        println!("Enter accepts defaults; Ctrl+C cancels.\n");
    }
    let existing_key = crate::secret::check_keypair(&secret_path)?;
    let existing_records = match &records_path {
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

    if let (Some(records), Some(path)) = (&prepared_records, &records_path) {
        crate::dns_records::DnsRecords::parse(&records.contents, path)?
            .sign(&existing_key.unwrap_or_else(pkarr::Keypair::random), None)?;
    }
    if interactive {
        println!("\nReview");
        if let Some(records) = &prepared_records {
            println!(
                "  Address: {}:{}\n  Records: A + HTTPS",
                records.address, records.port
            );
        } else if records_path.is_some() {
            println!("  DNS records: keep existing");
        } else {
            println!("  Local DNS records: not needed");
        }
        let file_paths: Vec<_> = [&config_path, &secret_path]
            .into_iter()
            .chain(records_path.iter())
            .map(|path| path.as_path())
            .collect();
        let has_missing_files = review_files(&file_paths, &directory)?;
        if has_missing_files {
            let answer = prompt("\nCreate files? [Y/n]", None)?;
            if !answer.is_empty() && !answer.eq_ignore_ascii_case("y") {
                println!("Setup cancelled. No files created.");
                return Ok(());
            }
        }
        if !has_missing_files {
            println!("\nAll files already exist and are valid.");
        }
    }
    create_file_if_missing(&config_path, include_str!("../config.example.toml"))?;
    let keypair = crate::secret::load_or_create_keypair(&secret_path)?;
    if let (Some(records), Some(path)) = (prepared_records, &records_path) {
        create_file_if_missing(path, &records.contents)?;
    }
    if let Some(path) = &records_path {
        crate::dns_records::DnsRecords::load(path)?.sign(&keypair, None)?;
    }
    println!("\nSetup complete. Nothing has been published.");
    println!("Public Key Domain: {}", keypair.public_key());
    if interactive {
        print_next_steps(
            &config_path,
            records_path.as_deref(),
            args.directory.is_some(),
        );
    }
    Ok(())
}

/// The reviewed endpoint and the corresponding complete DNS records file.
struct PreparedRecords {
    address: Ipv4Addr,
    port: u16,
    contents: String,
}

async fn prepare_records(args: &InitArgs) -> Result<PreparedRecords> {
    if !args.non_interactive {
        println!("Public address\n");
        println!("Your DNS records tell clients where to connect.");
        println!("Set the public IP and port that lead to this proxy.\n");
    }
    let suggested = match args.public_ip {
        Some(ip) => {
            validate_public_ipv4(ip)?;
            Some(ip)
        }
        None if args.non_interactive => {
            bail!("Missing DNS records: --non-interactive requires --public-ip")
        }
        None => {
            println!("Looking up your public IPv4...");
            match detect_public_ipv4().await {
                Ok(ip) => Some(ip),
                Err(error) => {
                    tracing::debug!("Public IPv4 detection failed: {error:#}");
                    println!("Could not detect an address. Enter it manually.");
                    None
                }
            }
        }
    };
    let ip = if !args.non_interactive {
        println!("Verify the suggested address is reachable by your clients.\n");
        loop {
            let input = prompt(
                "Public IPv4 address",
                suggested.map(|ip| ip.to_string()).as_deref(),
            )?;
            match parse_public_ipv4(&input) {
                Ok(ip) => break ip,
                Err(error) => println!("{error}"),
            }
        }
    } else {
        suggested.expect("non-interactive requires explicit IP")
    };
    let port = if !args.non_interactive {
        loop {
            let input = prompt("Public TLS port", Some(&args.port.to_string()))?;
            match input.parse::<u16>() {
                Ok(port) if port > 0 => break port,
                _ => println!("Enter a port between 1 and 65535."),
            }
        }
    } else {
        args.port
    };
    Ok(PreparedRecords {
        address: ip,
        port,
        contents: starter_records(ip, port),
    })
}

/// Show file actions using relative names where possible, and report whether confirmation is needed.
fn review_files(paths: &[&Path], directory: &Path) -> Result<bool> {
    println!();
    let mut has_missing_files = false;
    for path in paths {
        let exists = path_exists(path)?;
        has_missing_files |= !exists;
        let name = path.strip_prefix(directory).unwrap_or(path);
        println!(
            "  {:<24} {}",
            name.display(),
            if exists { "keep existing" } else { "create" }
        );
    }
    Ok(has_missing_files)
}

fn print_next_steps(config_path: &Path, records_path: Option<&Path>, custom_directory: bool) {
    println!(
        "\nReview listener/backend settings in {}.",
        config_path.display()
    );
    if let Some(path) = records_path {
        println!(
            "Review {} and ensure the advertised port is reachable.",
            path.display()
        );
    }
    let config_arg = if custom_directory {
        format!(" --config {config_path:?}")
    } else {
        String::new()
    };
    println!("\nThen run:\n  pubky-tls-proxy{config_arg} --check\n  pubky-tls-proxy{config_arg}");
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    print!(
        "{label}{}: ",
        default
            .map(|value| format!(" [{value}]"))
            .unwrap_or_default()
    );
    io::stdout().flush()?;
    let mut input = String::new();
    ensure!(
        io::stdin().read_line(&mut input)? > 0,
        "Input closed; setup cancelled"
    );
    let input = input.trim();
    Ok(if input.is_empty() {
        default.unwrap_or("")
    } else {
        input
    }
    .to_owned())
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Cannot inspect {}", path.display())),
    }
}

/// Persist complete contents without replacing any existing path, including symlinks.
fn create_file_if_missing(path: &Path, contents: &str) -> Result<()> {
    if path_exists(path)? {
        return Ok(());
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
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
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
        .context("Enter a valid public IPv4 address")?;
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
