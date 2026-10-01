//! Settings from the config file and the command line, merged and validated.
//!
//! Precedence: command line > config file > built-in defaults.
//!
//! Configuration must exist before startup. Relative paths, from the file and from the
//! command line, are resolved against the directory of that config file.

use crate::{cli::Args, proxy::ConnectionLimits};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use std::{
    fs,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::Semaphore;
use tracing::warn;
use url::Url;

const CONFIG_DIR_NAME: &str = ".pubky-tls-proxy";
const CONFIG_FILE_NAME: &str = "config.toml";
#[cfg(test)]
const CONFIG_TEMPLATE: &str = include_str!("../config.example.toml");

const DEFAULT_LISTEN_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8443));
const DEFAULT_HTTP_BACKEND_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6286));
const DEFAULT_REPUBLISH_INTERVAL_SECS: u64 = 60 * 60;
/// Relative to the config directory, like every relative path.
const DEFAULT_PACKET_CACHE_FILE: &str = "pkarr-packet.cache";
const DEFAULT_DNS_RECORDS_FILE: &str = "dns-records.toml";

/// Same list as `mainline::rpc::DEFAULT_BOOTSTRAP_NODES` (`mainline` 8), which `pkarr` doesn't re-export.
const DEFAULT_DHT_BOOTSTRAP_NODES: [&str; 4] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
    "relay.pkarr.org:6881",
];

/// The config file as written by the user. Every key is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    secret_key_file: Option<PathBuf>,
    listen_addrs: Option<Vec<SocketAddr>>,
    http_backend_addr: Option<SocketAddr>,
    tls_passthrough_backend_addr: Option<SocketAddr>,
    plain_http: Option<bool>,
    proxy_protocol: Option<bool>,
    max_connections: Option<usize>,
    rpk_handshake_timeout_secs: Option<u64>,
    backend_setup_timeout_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pkarr: PkarrFileConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PkarrFileConfig {
    publish: Option<bool>,
    mode: Option<PkarrMode>,
    republish_interval_secs: Option<u64>,
    packet_cache_file: Option<PathBuf>,
    dht_bootstrap_nodes: Option<Vec<String>>,
    relay_urls: Option<Vec<String>>,
    dns_records_file: Option<PathBuf>,
}

/// The authoritative source used by the publisher; file absence never selects a mode.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PkarrMode {
    #[default]
    LocalRecords,
    ExternalPacket,
}

/// Validated settings with all paths resolved and defaults applied.
#[derive(Debug)]
pub struct Settings {
    /// The required config file that was read.
    pub config_file: PathBuf,
    pub secret_key_file: PathBuf,
    pub listen_addrs: Vec<SocketAddr>,
    pub http_backend_addr: SocketAddr,
    pub tls_passthrough_backend_addr: Option<SocketAddr>,
    pub plain_http: bool,
    pub send_proxy_protocol: bool,
    pub limits: ConnectionLimits,
    /// Required in local-records mode when publishing is enabled.
    pub dns_records_file: Option<PathBuf>,
    /// `None` if PKARR publishing and republishing are disabled.
    pub pkarr_publish: Option<PkarrPublishSettings>,
}

/// How to publish and republish the PKARR packet. At least one network is enabled.
#[derive(Debug)]
pub struct PkarrPublishSettings {
    pub republish_interval: Duration,
    /// Where the last known PKARR packet is kept, see `packet_cache.rs`.
    pub packet_cache_file: PathBuf,
    /// Present when the operator owns the complete record set locally.
    pub dns_records_file: Option<PathBuf>,
    /// Resolved DHT bootstrap nodes. `None` disables the DHT.
    pub dht_bootstrap_nodes: Option<Vec<SocketAddrV4>>,
    /// `None` disables relays.
    pub relay_urls: Option<Vec<Url>>,
}

impl Settings {
    /// Reads the required config file, merges it with `args` and validates the result.
    ///
    /// # Errors
    ///
    /// Fails if the selected config or required records file is missing,
    /// the config file is invalid, or a PKARR network setting is unusable.
    pub fn load(args: Args) -> Result<Self> {
        Self::load_with_home_dir(args, std::env::home_dir())
    }

    fn load_with_home_dir(args: Args, home_dir: Option<PathBuf>) -> Result<Self> {
        let location = ConfigLocation::find(args.config.as_deref(), home_dir)?;
        let file = read_config_file(&location.file)?;

        let secret_key_file = args
            .secret_key_file
            .clone()
            .or(file.secret_key_file.clone())
            .unwrap_or_else(|| PathBuf::from("secret"));

        let listen_addrs = non_empty(args.listen_addrs.clone())
            .or(file.listen_addrs.clone())
            .unwrap_or_else(|| vec![DEFAULT_LISTEN_ADDR]);
        ensure!(!listen_addrs.is_empty(), "listen_addrs must not be empty");

        let limits = connection_limits(&args, &file)?;

        let is_publish_enabled = !args.no_pkarr_publish && file.pkarr.publish.unwrap_or(true);
        let dns_records_file = records_path(&args, &file, &location)?;
        if let Some(path) = &dns_records_file {
            ensure!(path.is_file(), "DNS records file {path:?} does not exist. Run pubky-tls-proxy init --directory {:?}, then review the records before starting.", location.base_dir);
        }
        let pkarr_publish = if is_publish_enabled {
            Some(pkarr_publish_settings(
                &args,
                &file,
                &location,
                dns_records_file.clone(),
            )?)
        } else {
            None
        };

        Ok(Self {
            config_file: location.file.clone(),
            secret_key_file: location.resolve(&secret_key_file),
            listen_addrs,
            http_backend_addr: args
                .http_backend_addr
                .or(file.http_backend_addr)
                .unwrap_or(DEFAULT_HTTP_BACKEND_ADDR),
            tls_passthrough_backend_addr: args
                .tls_passthrough_backend_addr
                .or(file.tls_passthrough_backend_addr),
            plain_http: !args.no_plain_http && file.plain_http.unwrap_or(true),
            send_proxy_protocol: !args.no_proxy_protocol && file.proxy_protocol.unwrap_or(true),
            limits,
            dns_records_file,
            pkarr_publish,
        })
    }
}

/// Merges connection limits and checks them before a listener or semaphore is created.
fn connection_limits(args: &Args, file: &FileConfig) -> Result<ConnectionLimits> {
    let defaults = ConnectionLimits::default();
    let max_connections = args
        .max_connections
        .or(file.max_connections)
        .unwrap_or(defaults.max_connections);
    let rpk_handshake_timeout_secs = args
        .rpk_handshake_timeout_secs
        .or(file.rpk_handshake_timeout_secs)
        .unwrap_or(defaults.rpk_handshake_timeout.as_secs());
    let backend_setup_timeout_secs = args
        .backend_setup_timeout_secs
        .or(file.backend_setup_timeout_secs)
        .unwrap_or(defaults.backend_setup_timeout.as_secs());
    let idle_timeout_secs = args
        .idle_timeout_secs
        .or(file.idle_timeout_secs)
        .unwrap_or(defaults.idle_timeout.as_secs());

    ensure!(
        max_connections > 0 && max_connections <= Semaphore::MAX_PERMITS,
        "max_connections must be between 1 and {}",
        Semaphore::MAX_PERMITS
    );
    ensure!(
        rpk_handshake_timeout_secs > 0,
        "rpk_handshake_timeout_secs must be positive"
    );
    ensure!(
        backend_setup_timeout_secs > 0,
        "backend_setup_timeout_secs must be positive"
    );
    ensure!(idle_timeout_secs > 0, "idle_timeout_secs must be positive");

    Ok(ConnectionLimits {
        max_connections,
        rpk_handshake_timeout: Duration::from_secs(rpk_handshake_timeout_secs),
        backend_setup_timeout: Duration::from_secs(backend_setup_timeout_secs),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
    })
}

/// Where the config file is and which directory relative paths are resolved against.
struct ConfigLocation {
    file: PathBuf,
    base_dir: PathBuf,
}

impl ConfigLocation {
    fn find(explicit_config_file: Option<&Path>, home_dir: Option<PathBuf>) -> Result<Self> {
        let config_file = match explicit_config_file {
            Some(path) => path.to_path_buf(),
            None => home_dir
                .context("Cannot locate home directory; supply --config")?
                .join(CONFIG_DIR_NAME)
                .join(CONFIG_FILE_NAME),
        };
        let base_dir = config_file.parent().unwrap_or(Path::new(".")).to_path_buf();
        ensure!(config_file.is_file(), "Config file {config_file:?} does not exist. Run pubky-tls-proxy init --directory {:?} to prepare it.", base_dir);
        Ok(Self {
            file: config_file,
            base_dir,
        })
    }

    /// Resolves `path` against the base directory. Absolute paths are returned unchanged.
    fn resolve(&self, path: &Path) -> PathBuf {
        self.base_dir.join(path)
    }
}

fn read_config_file(path: &Path) -> Result<FileConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read config file {path:?}"))?;
    toml::from_str(&content).with_context(|| format!("Invalid config file {path:?}"))
}

/// Resolved setup settings, including existing paths and values shown in the next steps.
pub struct InitSettings {
    pub secret_key_file: PathBuf,
    pub dns_records_file: Option<PathBuf>,
    pub http_backend_addr: SocketAddr,
    pub pkarr_mode: Option<PkarrMode>,
}

/// Validate existing settings offline and resolve the paths init should fill in.
/// Missing files are allowed here; normal startup requires them.
pub fn init_settings(config_path: &Path) -> Result<InitSettings> {
    let file = match fs::symlink_metadata(config_path) {
        Ok(_) => read_config_file(config_path)?,
        Err(error) if error.kind() == ErrorKind::NotFound => FileConfig::default(),
        Err(error) => return Err(error).context("Failed to inspect config file"),
    };
    connection_limits(&Args::default(), &file)?;
    ensure!(
        file.listen_addrs
            .as_ref()
            .is_none_or(|addrs| !addrs.is_empty()),
        "listen_addrs must not be empty"
    );
    let location = ConfigLocation {
        file: config_path.to_path_buf(),
        base_dir: config_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
    };
    let dns_records_file = records_path(&Args::default(), &file, &location)?;
    if file.pkarr.publish.unwrap_or(true) {
        // Reuse offline check validation, without requiring the records file yet.
        let check_args = Args {
            check: true,
            ..Args::default()
        };
        pkarr_publish_settings(&check_args, &file, &location, None)?;
    }
    let parent = config_path.parent().unwrap_or(Path::new("."));
    Ok(InitSettings {
        secret_key_file: parent.join(file.secret_key_file.unwrap_or_else(|| "secret".into())),
        dns_records_file,
        http_backend_addr: file.http_backend_addr.unwrap_or(DEFAULT_HTTP_BACKEND_ADDR),
        pkarr_mode: file
            .pkarr
            .publish
            .unwrap_or(true)
            .then(|| file.pkarr.mode.unwrap_or_default()),
    })
}

fn pkarr_publish_settings(
    args: &Args,
    file: &FileConfig,
    location: &ConfigLocation,
    dns_records_file: Option<PathBuf>,
) -> Result<PkarrPublishSettings> {
    let republish_interval_secs = args
        .pkarr_republish_interval_secs
        .or(file.pkarr.republish_interval_secs)
        .unwrap_or(DEFAULT_REPUBLISH_INTERVAL_SECS);
    ensure!(
        republish_interval_secs > 0,
        "The republish interval must be at least 1 second"
    );

    let packet_cache_file = args
        .pkarr_packet_cache_file
        .clone()
        .or(file.pkarr.packet_cache_file.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACKET_CACHE_FILE));

    // A configured list replaces the defaults. An empty list disables the network.
    let bootstrap_nodes = if args.no_pkarr_dht {
        Vec::new()
    } else {
        non_empty(args.pkarr_dht_bootstrap_nodes.clone())
            .or(file.pkarr.dht_bootstrap_nodes.clone())
            .unwrap_or_else(|| DEFAULT_DHT_BOOTSTRAP_NODES.map(String::from).to_vec())
    };
    let relay_urls = if args.no_pkarr_relays {
        Vec::new()
    } else {
        non_empty(args.pkarr_relay_urls.clone())
            .or(file.pkarr.relay_urls.clone())
            .unwrap_or_else(|| pkarr::DEFAULT_RELAYS.map(String::from).to_vec())
    };

    let dht_bootstrap_nodes = if bootstrap_nodes.is_empty() {
        None
    } else if args.check {
        // --check validates local input without contacting DNS or any PKARR network.
        Some(Vec::new())
    } else {
        Some(resolve_bootstrap_nodes(&bootstrap_nodes)?)
    };
    let relay_urls = if relay_urls.is_empty() {
        None
    } else {
        Some(parse_relay_urls(&relay_urls)?)
    };
    ensure!(
        dht_bootstrap_nodes.is_some() || relay_urls.is_some(),
        "PKARR publishing needs the DHT or at least one relay. Configure one or disable publishing."
    );

    Ok(PkarrPublishSettings {
        republish_interval: Duration::from_secs(republish_interval_secs),
        packet_cache_file: location.resolve(&packet_cache_file),
        dns_records_file,
        dht_bootstrap_nodes,
        relay_urls,
    })
}

fn records_path(
    args: &Args,
    file: &FileConfig,
    location: &ConfigLocation,
) -> Result<Option<PathBuf>> {
    let configured = args
        .dns_records_file
        .clone()
        .or(file.pkarr.dns_records_file.clone());
    let mode = args.pkarr_mode.or(file.pkarr.mode).unwrap_or_default();
    if mode == PkarrMode::ExternalPacket {
        ensure!(configured.is_none(), "external-packet mode conflicts with dns_records_file; remove the records path or select local-records mode");
        return Ok(None);
    }
    if args.no_pkarr_publish || !file.pkarr.publish.unwrap_or(true) {
        return Ok(None);
    }
    Ok(Some(location.resolve(
        &configured.unwrap_or_else(|| DEFAULT_DNS_RECORDS_FILE.into()),
    )))
}

/// Resolves `host:port` bootstrap nodes to the IPv4 addresses mainline can use.
///
/// Mainline would silently drop nodes that don't resolve to IPv4, so we warn about them here.
fn resolve_bootstrap_nodes(bootstrap_nodes: &[String]) -> Result<Vec<SocketAddrV4>> {
    let mut resolved = Vec::new();
    for node in bootstrap_nodes {
        let ipv4_addrs: Vec<SocketAddrV4> = match node.to_socket_addrs() {
            Ok(addrs) => addrs
                .filter_map(|addr| match addr {
                    SocketAddr::V4(addr) => Some(addr),
                    SocketAddr::V6(_) => None,
                })
                .collect(),
            Err(error) => {
                warn!("Ignoring DHT bootstrap node {node:?}: {error}");
                continue;
            }
        };
        if ipv4_addrs.is_empty() {
            warn!("Ignoring DHT bootstrap node {node:?}: no IPv4 address");
        }
        for addr in ipv4_addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }

    if resolved.is_empty() {
        bail!("None of the DHT bootstrap nodes {bootstrap_nodes:?} resolved to an IPv4 address");
    }
    Ok(resolved)
}

fn parse_relay_urls(relays: &[String]) -> Result<Vec<Url>> {
    relays
        .iter()
        .map(|relay| {
            Url::parse(relay).with_context(|| format!("Invalid PKARR relay URL {relay:?}"))
        })
        .collect()
}

/// Repeatable CLI flags are empty when not given; treat that as "not set".
fn non_empty<T>(values: Vec<T>) -> Option<Vec<T>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A fake home directory, optionally containing ~/.pubky-tls-proxy/config.toml.
    struct FakeHome {
        dir: TempDir,
    }

    impl FakeHome {
        fn without_config() -> Self {
            Self {
                dir: TempDir::new().unwrap(),
            }
        }

        fn with_config(config: &str) -> Self {
            let home = Self::without_config();
            fs::create_dir(home.config_dir()).unwrap();
            fs::write(home.config_dir().join(CONFIG_FILE_NAME), config).unwrap();
            fs::write(
                home.config_dir().join(DEFAULT_DNS_RECORDS_FILE),
                "records = []",
            )
            .unwrap();
            home
        }

        fn config_dir(&self) -> PathBuf {
            self.dir.path().join(CONFIG_DIR_NAME)
        }

        fn load(&self, args: Args) -> Result<Settings> {
            Settings::load_with_home_dir(args, Some(self.dir.path().to_path_buf()))
        }
    }

    /// Publishing is disabled so tests don't resolve the default bootstrap nodes over DNS.
    fn args_with_secret_key_file() -> Args {
        Args {
            secret_key_file: Some("secret".into()),
            no_pkarr_publish: true,
            ..Args::default()
        }
    }

    #[test]
    fn prepared_config_uses_defaults() {
        let home = FakeHome::with_config(CONFIG_TEMPLATE);
        let args = Args {
            no_pkarr_publish: false,
            no_pkarr_dht: true,
            ..args_with_secret_key_file()
        };

        let settings = home.load(args).unwrap();

        let config_file = home.config_dir().join(CONFIG_FILE_NAME);
        assert_eq!(settings.config_file, config_file.clone());
        let template = fs::read_to_string(&config_file).unwrap();
        assert_eq!(template, CONFIG_TEMPLATE);
        assert_eq!(
            toml::from_str::<FileConfig>(&template)
                .unwrap()
                .secret_key_file,
            None
        );
        assert_eq!(settings.listen_addrs, vec![DEFAULT_LISTEN_ADDR]);
        assert_eq!(settings.http_backend_addr, DEFAULT_HTTP_BACKEND_ADDR);
        assert_eq!(settings.tls_passthrough_backend_addr, None);
        assert!(settings.plain_http);
        assert!(settings.send_proxy_protocol);
        assert_eq!(settings.limits.max_connections, 1024);
        assert_eq!(
            settings.limits.rpk_handshake_timeout,
            Duration::from_secs(10)
        );
        assert_eq!(
            settings.limits.backend_setup_timeout,
            Duration::from_secs(10)
        );
        assert_eq!(settings.limits.idle_timeout, Duration::from_secs(300));
        let publish = settings.pkarr_publish.unwrap();
        assert_eq!(publish.republish_interval, Duration::from_secs(3600));
        assert_eq!(
            publish.packet_cache_file,
            home.config_dir().join("pkarr-packet.cache")
        );
        let default_relays: Vec<Url> = pkarr::DEFAULT_RELAYS
            .iter()
            .map(|r| r.parse().unwrap())
            .collect();
        assert_eq!(publish.relay_urls, Some(default_relays));
    }

    #[test]
    fn subsequent_starts_preserve_edited_config() {
        let home = FakeHome::with_config("");
        let config_file = home.config_dir().join(CONFIG_FILE_NAME);
        home.load(args_with_secret_key_file()).unwrap();
        let edited = "listen_addrs = ['127.0.0.1:9000']\n";
        fs::write(&config_file, edited).unwrap();

        let settings = home.load(args_with_secret_key_file()).unwrap();

        assert_eq!(fs::read_to_string(&config_file).unwrap(), edited);
        assert_eq!(
            settings.listen_addrs,
            vec!["127.0.0.1:9000".parse().unwrap()]
        );
    }

    #[test]
    fn config_file_overrides_defaults() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret.hex"
            listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
            http_backend_addr = "127.0.0.1:8080"
            tls_passthrough_backend_addr = "127.0.0.1:8443"
            plain_http = false
            proxy_protocol = false

            [pkarr]
            republish_interval_secs = 600
            packet_cache_file = "state/pkarr-packet.cache"
            dht_bootstrap_nodes = ["127.0.0.1:6881"]
            relay_urls = ["https://relay.example.com"]
            "#,
        );

        let settings = home.load(Args::default()).unwrap();

        assert_eq!(
            settings.config_file,
            home.config_dir().join(CONFIG_FILE_NAME)
        );
        assert_eq!(
            settings.secret_key_file,
            home.config_dir().join("secret.hex")
        );
        assert_eq!(
            settings.listen_addrs,
            vec![
                "0.0.0.0:80".parse().unwrap(),
                "0.0.0.0:443".parse().unwrap()
            ]
        );
        assert_eq!(
            settings.http_backend_addr,
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            settings.tls_passthrough_backend_addr,
            Some("127.0.0.1:8443".parse().unwrap())
        );
        assert!(!settings.plain_http);
        assert!(!settings.send_proxy_protocol);
        let publish = settings.pkarr_publish.unwrap();
        assert_eq!(publish.republish_interval, Duration::from_secs(600));
        assert_eq!(
            publish.packet_cache_file,
            home.config_dir().join("state/pkarr-packet.cache")
        );
        assert_eq!(
            publish.dht_bootstrap_nodes,
            Some(vec!["127.0.0.1:6881".parse().unwrap()])
        );
        assert_eq!(
            publish.relay_urls,
            Some(vec!["https://relay.example.com".parse().unwrap()])
        );
    }

    #[test]
    fn command_line_overrides_config_file() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "from-file"
            listen_addrs = ["0.0.0.0:80"]
            http_backend_addr = "127.0.0.1:8080"
            plain_http = true
            tls_passthrough_backend_addr = "127.0.0.1:8443"
            [pkarr]
            republish_interval_secs = 600
            packet_cache_file = "from-file.cache"
            dns_records_file = "missing-from-file.toml"
            dht_bootstrap_nodes = ["127.0.0.1:6881"]
            relay_urls = ["https://relay.example.com"]
            "#,
        );
        fs::write(home.config_dir().join("from-cli.toml"), "records = []").unwrap();
        let args = Args {
            secret_key_file: Some("from-cli".into()),
            listen_addrs: vec!["127.0.0.1:9000".parse().unwrap()],
            http_backend_addr: Some("127.0.0.1:9001".parse().unwrap()),
            tls_passthrough_backend_addr: Some("127.0.0.1:9443".parse().unwrap()),
            pkarr_republish_interval_secs: Some(60),
            pkarr_packet_cache_file: Some("/var/lib/proxy/pkarr-packet.cache".into()),
            dns_records_file: Some("from-cli.toml".into()),
            pkarr_dht_bootstrap_nodes: vec!["127.0.0.2:6881".into()],
            pkarr_relay_urls: vec!["https://other-relay.example.com".into()],
            no_proxy_protocol: true,
            no_plain_http: true,
            ..Args::default()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(settings.secret_key_file, home.config_dir().join("from-cli"));
        assert_eq!(
            settings.tls_passthrough_backend_addr,
            Some("127.0.0.1:9443".parse().unwrap())
        );
        assert_eq!(
            settings.dns_records_file,
            Some(home.config_dir().join("from-cli.toml"))
        );
        assert_eq!(
            settings.listen_addrs,
            vec!["127.0.0.1:9000".parse().unwrap()]
        );
        assert_eq!(
            settings.http_backend_addr,
            "127.0.0.1:9001".parse().unwrap()
        );
        assert!(!settings.plain_http);
        assert!(!settings.send_proxy_protocol);
        let publish = settings.pkarr_publish.unwrap();
        assert_eq!(publish.republish_interval, Duration::from_secs(60));
        assert_eq!(publish.dns_records_file, settings.dns_records_file);
        assert_eq!(
            publish.packet_cache_file,
            PathBuf::from("/var/lib/proxy/pkarr-packet.cache")
        );
        assert_eq!(
            publish.dht_bootstrap_nodes,
            Some(vec!["127.0.0.2:6881".parse().unwrap()])
        );
        assert_eq!(
            publish.relay_urls,
            Some(vec!["https://other-relay.example.com".parse().unwrap()])
        );
    }

    #[test]
    fn relative_cli_paths_resolve_against_config_dir_on_first_start() {
        let home = FakeHome::with_config("");

        let settings = home.load(args_with_secret_key_file()).unwrap();

        assert_eq!(settings.secret_key_file, home.config_dir().join("secret"));
    }

    #[test]
    fn absolute_paths_are_kept() {
        let home = FakeHome::with_config("");
        let args = Args {
            secret_key_file: Some("/etc/pkdns-demo/secret.hex".into()),
            ..args_with_secret_key_file()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(
            settings.secret_key_file,
            PathBuf::from("/etc/pkdns-demo/secret.hex")
        );
    }

    #[test]
    fn explicit_config_file_is_used_and_its_dir_is_the_base_dir() {
        let home = FakeHome::without_config();
        let other_dir = TempDir::new().unwrap();
        let config_file = other_dir.path().join("proxy.toml");
        fs::write(&config_file, r#"secret_key_file = "secret.hex""#).unwrap();
        let args = Args {
            config: Some(config_file.clone()),
            no_pkarr_publish: true,
            ..Args::default()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(settings.config_file, config_file);
        assert_eq!(
            settings.secret_key_file,
            other_dir.path().join("secret.hex")
        );
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        let home = FakeHome::without_config();
        let args = Args {
            config: Some("/does/not/exist.toml".into()),
            ..args_with_secret_key_file()
        };

        let error = home.load(args).unwrap_err();

        assert!(error.to_string().contains("does not exist"), "{error}");
        assert!(!home.config_dir().exists());
    }

    #[test]
    fn unknown_config_key_is_an_error() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret"
            [pkarr]
            relay = ["https://typo.example.com"]
            "#,
        );

        let error = home.load(Args::default()).unwrap_err();

        assert!(
            format!("{error:#}").contains("unknown field `relay`"),
            "{error:#}"
        );
    }

    #[test]
    fn removed_config_keys_are_rejected_even_when_publishing_is_disabled() {
        for (config, field) in [
            ("secret_file = 'secret'", "secret_file"),
            ("https_backend_addr = '127.0.0.1:443'", "https_backend_addr"),
            ("handshake_timeout_secs = 10", "handshake_timeout_secs"),
            ("backend_timeout_secs = 10", "backend_timeout_secs"),
            ("[republish]\nenabled = false", "republish"),
            ("[pkarr]\nrecords_file = 'dns-records.toml'", "records_file"),
            ("[pkarr]\nbootstrap_nodes = []", "bootstrap_nodes"),
            ("[pkarr]\nrelays = []", "relays"),
            ("[pkarr]\nenabled = false", "enabled"),
            ("[pkarr]\ninterval_secs = 60", "interval_secs"),
            ("[pkarr]\ncache_file = 'packet.cache'", "cache_file"),
        ] {
            let home = FakeHome::with_config(config);
            let error = home.load(args_with_secret_key_file()).unwrap_err();
            assert!(
                format!("{error:#}").contains(&format!("unknown field `{field}`")),
                "{config}: {error:#}"
            );
        }
    }

    #[test]
    fn disabled_publishing_does_not_require_records_for_startup_or_check() {
        let home = FakeHome::with_config(
            "[pkarr]\npublish = true\ndns_records_file = 'missing.toml'\ndht_bootstrap_nodes = []\nrelay_urls = []\n",
        );
        let settings = home.load(args_with_secret_key_file()).unwrap();
        assert!(settings.pkarr_publish.is_none());
        assert!(settings.dns_records_file.is_none());

        let settings = home
            .load(Args {
                check: true,
                ..args_with_secret_key_file()
            })
            .unwrap();
        assert!(settings.dns_records_file.is_none());

        fs::write(home.config_dir().join("missing.toml"), "records = []").unwrap();
        let settings = home
            .load(Args {
                check: true,
                ..args_with_secret_key_file()
            })
            .unwrap();
        assert!(settings.pkarr_publish.is_none());
        assert!(settings.dns_records_file.is_none());
    }

    #[test]
    fn zero_republish_interval_is_rejected() {
        let home = FakeHome::with_config("[pkarr]\nrepublish_interval_secs = 0\n");
        let error = home.load(Args::default()).unwrap_err();
        assert!(
            error.to_string().contains("republish interval"),
            "{error:#}"
        );
    }

    #[test]
    fn uncommented_starter_config_uses_canonical_schema() {
        let example = CONFIG_TEMPLATE
            .lines()
            .map(|line| {
                line.strip_prefix("# ")
                    .filter(|content| content.contains(" = "))
                    .unwrap_or(line)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let home = FakeHome::with_config(&example);
        fs::write(
            home.config_dir().join(DEFAULT_DNS_RECORDS_FILE),
            "records = []",
        )
        .unwrap();
        let settings = home
            .load(Args {
                check: true,
                ..Args::default()
            })
            .unwrap();
        assert_eq!(settings.secret_key_file, home.config_dir().join("secret"));
        let publish = settings.pkarr_publish.unwrap();
        assert_eq!(
            publish.dns_records_file,
            Some(home.config_dir().join(DEFAULT_DNS_RECORDS_FILE))
        );
        assert_eq!(
            publish.packet_cache_file,
            home.config_dir().join(DEFAULT_PACKET_CACHE_FILE)
        );
        assert_eq!(publish.republish_interval, Duration::from_secs(3600));
    }

    #[test]
    fn secret_key_file_defaults_to_config_directory() {
        let home = FakeHome::with_config("");

        let settings = home
            .load(Args {
                no_pkarr_publish: true,
                ..Args::default()
            })
            .unwrap();
        assert_eq!(settings.secret_key_file, home.config_dir().join("secret"));
    }

    #[test]
    fn empty_relay_list_disables_relays() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret"
            [pkarr]
            dht_bootstrap_nodes = ["127.0.0.1:6881"]
            relay_urls = []
            "#,
        );

        let publish = home.load(Args::default()).unwrap().pkarr_publish.unwrap();

        assert_eq!(publish.relay_urls, None);
        assert!(publish.dht_bootstrap_nodes.is_some());
    }

    #[test]
    fn no_pkarr_dht_flag_disables_dht() {
        let home = FakeHome::with_config("");
        let args = Args {
            no_pkarr_publish: false,
            no_pkarr_dht: true,
            ..args_with_secret_key_file()
        };

        let publish = home.load(args).unwrap().pkarr_publish.unwrap();

        assert_eq!(publish.dht_bootstrap_nodes, None);
        assert!(publish.relay_urls.is_some());
    }

    #[test]
    fn publishing_without_any_network_is_an_error() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret"
            [pkarr]
            dht_bootstrap_nodes = []
            relay_urls = []
            "#,
        );

        let error = home.load(Args::default()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("PKARR publishing needs the DHT or at least one relay"),
            "{error}"
        );
    }

    #[test]
    fn no_network_is_fine_when_publishing_is_disabled() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret"
            [pkarr]
            publish = false
            dht_bootstrap_nodes = []
            relay_urls = []
            "#,
        );

        let settings = home.load(Args::default()).unwrap();

        assert!(settings.pkarr_publish.is_none());
    }

    #[test]
    fn invalid_relay_url_is_an_error() {
        let home = FakeHome::with_config("");
        let args = Args {
            no_pkarr_publish: false,
            no_pkarr_dht: true,
            pkarr_relay_urls: vec!["not a url".into()],
            ..args_with_secret_key_file()
        };

        let error = home.load(args).unwrap_err();

        assert!(
            error.to_string().contains("Invalid PKARR relay URL"),
            "{error}"
        );
    }

    #[test]
    fn connection_limits_merge_config_and_command_line() {
        let home = FakeHome::with_config(
            r#"
            secret_key_file = "secret"
            max_connections = 50
            rpk_handshake_timeout_secs = 7
            backend_setup_timeout_secs = 8
            idle_timeout_secs = 90
        "#,
        );
        let args = Args {
            max_connections: Some(25),
            rpk_handshake_timeout_secs: Some(3),
            ..args_with_secret_key_file()
        };

        let limits = home.load(args).unwrap().limits;
        assert_eq!(limits.max_connections, 25);
        assert_eq!(limits.rpk_handshake_timeout, Duration::from_secs(3));
        assert_eq!(limits.backend_setup_timeout, Duration::from_secs(8));
        assert_eq!(limits.idle_timeout, Duration::from_secs(90));
    }

    #[test]
    fn invalid_connection_limits_are_rejected() {
        for invalid in [
            "max_connections = 0",
            "rpk_handshake_timeout_secs = 0",
            "backend_setup_timeout_secs = 0",
            "idle_timeout_secs = 0",
        ] {
            let home = FakeHome::with_config(&format!("secret_key_file = \"secret\"\n{invalid}\n"));
            assert!(home.load(args_with_secret_key_file()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn unresolvable_bootstrap_nodes_are_skipped() {
        let nodes = vec![
            "does-not-exist.invalid:6881".to_string(),
            "127.0.0.1:6881".to_string(),
        ];

        let resolved = resolve_bootstrap_nodes(&nodes).unwrap();

        assert_eq!(resolved, vec!["127.0.0.1:6881".parse().unwrap()]);
    }

    #[test]
    fn no_resolvable_bootstrap_node_is_an_error() {
        let nodes = vec!["does-not-exist.invalid:6881".to_string()];

        assert!(resolve_bootstrap_nodes(&nodes).is_err());
    }

    #[test]
    fn default_dns_records_file_is_detected_and_explicit_missing_file_fails() {
        let home = FakeHome::with_config("[pkarr]\ndht_bootstrap_nodes = []\n");
        let path = home.config_dir().join(DEFAULT_DNS_RECORDS_FILE);
        fs::write(&path, "records = []").unwrap();
        let settings = home.load(Args::default()).unwrap();
        assert_eq!(settings.dns_records_file, Some(path.clone()));
        assert_eq!(settings.pkarr_publish.unwrap().dns_records_file, Some(path));

        let error = home
            .load(Args {
                dns_records_file: Some("missing.toml".into()),
                ..Args::default()
            })
            .unwrap_err();
        assert!(error.to_string().contains("does not exist"), "{error}");
    }

    #[test]
    fn missing_default_config_fails_without_creating_files() {
        let home = FakeHome::without_config();
        let error = home.load(args_with_secret_key_file()).unwrap_err();
        assert!(error.to_string().contains("init --directory"), "{error}");
        assert!(!home.config_dir().exists());
    }

    #[test]
    fn missing_records_do_not_implicitly_select_external_mode() {
        let home = FakeHome::with_config("[pkarr]\ndht_bootstrap_nodes = []\n");
        fs::remove_file(home.config_dir().join(DEFAULT_DNS_RECORDS_FILE)).unwrap();
        for check in [false, true] {
            let error = home
                .load(Args {
                    check,
                    ..Args::default()
                })
                .unwrap_err();
            assert!(error.to_string().contains("DNS records file"), "{error}");
        }
        let settings = home
            .load(Args {
                pkarr_mode: Some(PkarrMode::ExternalPacket),
                ..Args::default()
            })
            .unwrap();
        assert!(settings.dns_records_file.is_none());
    }

    #[test]
    fn explicit_external_mode_ignores_default_file_and_rejects_explicit_records_path() {
        let home =
            FakeHome::with_config("[pkarr]\nmode = 'external-packet'\ndht_bootstrap_nodes = []\n");
        assert!(home
            .load(Args::default())
            .unwrap()
            .dns_records_file
            .is_none());
        let error = home
            .load(Args {
                dns_records_file: Some("custom.toml".into()),
                ..Args::default()
            })
            .unwrap_err();
        assert!(error.to_string().contains("conflicts"), "{error}");
        let local = home
            .load(Args {
                pkarr_mode: Some(PkarrMode::LocalRecords),
                ..Args::default()
            })
            .unwrap();
        assert!(local.dns_records_file.is_some());
    }
}
