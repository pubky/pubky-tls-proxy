//! Settings from the config file and the command line, merged and validated.
//!
//! Precedence: command line > config file > built-in defaults.
//!
//! The config file is `~/.pubky-tls-proxy/config.toml`, read only if it exists, or the file
//! passed with `--config`, which must exist. Relative paths, from the file and from the
//! command line, are resolved against the directory of that config file.

use crate::{cli::Args, proxy::ConnectionLimits};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::Semaphore;
use tracing::warn;
use url::Url;

const CONFIG_DIR_NAME: &str = ".pubky-tls-proxy";
const CONFIG_FILE_NAME: &str = "config.toml";

const DEFAULT_LISTEN_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8443));
const DEFAULT_HTTP_BACKEND_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6286));
const DEFAULT_REPUBLISH_INTERVAL_SECS: u64 = 60 * 60;
/// Relative to the config directory, like every relative path.
const DEFAULT_PACKET_CACHE_FILE: &str = "pkarr-packet.cache";

/// Same list as `mainline::rpc::DEFAULT_BOOTSTRAP_NODES` (mainline 8), which pkarr doesn't re-export.
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
    secret_file: Option<PathBuf>,
    listen_addrs: Option<Vec<SocketAddr>>,
    http_backend_addr: Option<SocketAddr>,
    https_backend_addr: Option<SocketAddr>,
    plain_http: Option<bool>,
    proxy_protocol: Option<bool>,
    max_connections: Option<usize>,
    handshake_timeout_secs: Option<u64>,
    backend_timeout_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    republish: RepublishFileConfig,
    #[serde(default)]
    pkarr: PkarrFileConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepublishFileConfig {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    cache_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PkarrFileConfig {
    bootstrap_nodes: Option<Vec<String>>,
    relays: Option<Vec<String>>,
}

/// Validated settings with all paths resolved and defaults applied.
#[derive(Debug)]
pub struct Settings {
    /// The config file that was read, if any.
    pub config_file: Option<PathBuf>,
    pub secret_file: PathBuf,
    pub listen_addrs: Vec<SocketAddr>,
    pub http_backend_addr: SocketAddr,
    pub https_backend_addr: Option<SocketAddr>,
    pub plain_http: bool,
    pub send_proxy_protocol: bool,
    pub limits: ConnectionLimits,
    /// `None` if republishing is disabled.
    pub republish: Option<RepublishSettings>,
}

/// How to republish the pkarr packet. At least one network is enabled.
#[derive(Debug)]
pub struct RepublishSettings {
    pub interval: Duration,
    /// Where the last known pkarr packet is kept, see `packet_cache.rs`.
    pub cache_file: PathBuf,
    /// Resolved DHT bootstrap nodes. `None` disables the DHT.
    pub dht_bootstrap_nodes: Option<Vec<SocketAddrV4>>,
    /// `None` disables relays.
    pub relays: Option<Vec<Url>>,
}

impl Settings {
    /// Reads the config file (if any), merges it with `args` and validates the result.
    ///
    /// # Errors
    ///
    /// Fails if `--config` points to a missing file, the config file is invalid, no secret
    /// file is configured, or a pkarr network setting is unusable.
    pub fn load(args: Args) -> Result<Self> {
        Self::load_with_home_dir(args, std::env::home_dir())
    }

    fn load_with_home_dir(args: Args, home_dir: Option<PathBuf>) -> Result<Self> {
        let location = ConfigLocation::find(args.config.as_deref(), home_dir)?;
        let file = match &location.file {
            Some(path) => read_config_file(path)?,
            None => FileConfig::default(),
        };

        let secret_file = args
            .secret_file
            .clone()
            .or(file.secret_file.clone())
            .context(
            "No secret file configured. Use --secret-file or set secret_file in the config file.",
        )?;

        let listen_addrs = non_empty(args.listen_addrs.clone())
            .or(file.listen_addrs.clone())
            .unwrap_or_else(|| vec![DEFAULT_LISTEN_ADDR]);
        ensure!(!listen_addrs.is_empty(), "listen_addrs must not be empty");

        let limits = connection_limits(&args, &file)?;

        let is_republish_enabled = !args.no_republish && file.republish.enabled.unwrap_or(true);
        let republish = if is_republish_enabled {
            Some(republish_settings(&args, &file, &location)?)
        } else {
            None
        };

        Ok(Self {
            config_file: location.file.clone(),
            secret_file: location.resolve(&secret_file),
            listen_addrs,
            http_backend_addr: args
                .http_backend_addr
                .or(file.http_backend_addr)
                .unwrap_or(DEFAULT_HTTP_BACKEND_ADDR),
            https_backend_addr: args.https_backend_addr.or(file.https_backend_addr),
            plain_http: !args.no_plain_http && file.plain_http.unwrap_or(true),
            send_proxy_protocol: !args.no_proxy_protocol && file.proxy_protocol.unwrap_or(true),
            limits,
            republish,
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
    let handshake_timeout_secs = args
        .handshake_timeout_secs
        .or(file.handshake_timeout_secs)
        .unwrap_or(defaults.handshake_timeout.as_secs());
    let backend_timeout_secs = args
        .backend_timeout_secs
        .or(file.backend_timeout_secs)
        .unwrap_or(defaults.backend_timeout.as_secs());
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
        handshake_timeout_secs > 0,
        "handshake_timeout_secs must be positive"
    );
    ensure!(
        backend_timeout_secs > 0,
        "backend_timeout_secs must be positive"
    );
    ensure!(idle_timeout_secs > 0, "idle_timeout_secs must be positive");

    Ok(ConnectionLimits {
        max_connections,
        handshake_timeout: Duration::from_secs(handshake_timeout_secs),
        backend_timeout: Duration::from_secs(backend_timeout_secs),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
    })
}

/// Where the config file is and which directory relative paths are resolved against.
struct ConfigLocation {
    /// An existing config file, or `None` if there is none to read.
    file: Option<PathBuf>,
    /// `None` if there is no home directory and no `--config`. Paths are then used as given.
    base_dir: Option<PathBuf>,
}

impl ConfigLocation {
    fn find(explicit_config_file: Option<&Path>, home_dir: Option<PathBuf>) -> Result<Self> {
        if let Some(config_file) = explicit_config_file {
            ensure!(
                config_file.is_file(),
                "Config file {config_file:?} does not exist"
            );
            return Ok(Self {
                file: Some(config_file.to_path_buf()),
                base_dir: config_file.parent().map(Path::to_path_buf),
            });
        }

        let Some(home_dir) = home_dir else {
            return Ok(Self {
                file: None,
                base_dir: None,
            });
        };
        let config_dir = home_dir.join(CONFIG_DIR_NAME);
        let default_config_file = config_dir.join(CONFIG_FILE_NAME);
        Ok(Self {
            file: default_config_file.is_file().then_some(default_config_file),
            base_dir: Some(config_dir),
        })
    }

    /// Resolves `path` against the base directory. Absolute paths are returned unchanged.
    fn resolve(&self, path: &Path) -> PathBuf {
        match &self.base_dir {
            Some(base_dir) => base_dir.join(path),
            None => path.to_path_buf(),
        }
    }
}

fn read_config_file(path: &Path) -> Result<FileConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read config file {path:?}"))?;
    toml::from_str(&content).with_context(|| format!("Invalid config file {path:?}"))
}

fn republish_settings(
    args: &Args,
    file: &FileConfig,
    location: &ConfigLocation,
) -> Result<RepublishSettings> {
    let interval_secs = args
        .republish_interval_secs
        .or(file.republish.interval_secs)
        .unwrap_or(DEFAULT_REPUBLISH_INTERVAL_SECS);
    ensure!(
        interval_secs > 0,
        "The republish interval must be at least 1 second"
    );

    let cache_file = args
        .packet_cache_file
        .clone()
        .or(file.republish.cache_file.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACKET_CACHE_FILE));

    // A configured list replaces the defaults. An empty list disables the network.
    let bootstrap_nodes = if args.no_pkarr_dht {
        Vec::new()
    } else {
        non_empty(args.pkarr_bootstrap_nodes.clone())
            .or(file.pkarr.bootstrap_nodes.clone())
            .unwrap_or_else(|| DEFAULT_DHT_BOOTSTRAP_NODES.map(String::from).to_vec())
    };
    let relays = if args.no_pkarr_relays {
        Vec::new()
    } else {
        non_empty(args.pkarr_relays.clone())
            .or(file.pkarr.relays.clone())
            .unwrap_or_else(|| pkarr::DEFAULT_RELAYS.map(String::from).to_vec())
    };

    let dht_bootstrap_nodes = if bootstrap_nodes.is_empty() {
        None
    } else {
        Some(resolve_bootstrap_nodes(&bootstrap_nodes)?)
    };
    let relays = if relays.is_empty() {
        None
    } else {
        Some(parse_relay_urls(&relays)?)
    };
    ensure!(
        dht_bootstrap_nodes.is_some() || relays.is_some(),
        "Republishing needs the DHT or at least one relay. Configure one or disable republishing."
    );

    Ok(RepublishSettings {
        interval: Duration::from_secs(interval_secs),
        cache_file: location.resolve(&cache_file),
        dht_bootstrap_nodes,
        relays,
    })
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
            Url::parse(relay).with_context(|| format!("Invalid pkarr relay URL {relay:?}"))
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
            home
        }

        fn config_dir(&self) -> PathBuf {
            self.dir.path().join(CONFIG_DIR_NAME)
        }

        fn load(&self, args: Args) -> Result<Settings> {
            Settings::load_with_home_dir(args, Some(self.dir.path().to_path_buf()))
        }
    }

    /// Republishing is disabled so tests don't resolve the default bootstrap nodes over DNS.
    fn args_with_secret_file() -> Args {
        Args {
            secret_file: Some("secret".into()),
            no_republish: true,
            ..Args::default()
        }
    }

    #[test]
    fn defaults_apply_without_config_file() {
        let home = FakeHome::without_config();
        let args = Args {
            no_republish: false,
            no_pkarr_dht: true,
            ..args_with_secret_file()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(settings.config_file, None);
        assert_eq!(settings.listen_addrs, vec![DEFAULT_LISTEN_ADDR]);
        assert_eq!(settings.http_backend_addr, DEFAULT_HTTP_BACKEND_ADDR);
        assert_eq!(settings.https_backend_addr, None);
        assert!(settings.plain_http);
        assert!(settings.send_proxy_protocol);
        assert_eq!(settings.limits.max_connections, 1024);
        assert_eq!(settings.limits.handshake_timeout, Duration::from_secs(10));
        assert_eq!(settings.limits.backend_timeout, Duration::from_secs(10));
        assert_eq!(settings.limits.idle_timeout, Duration::from_secs(300));
        let republish = settings.republish.unwrap();
        assert_eq!(republish.interval, Duration::from_secs(3600));
        assert_eq!(
            republish.cache_file,
            home.config_dir().join("pkarr-packet.cache")
        );
        let default_relays: Vec<Url> = pkarr::DEFAULT_RELAYS
            .iter()
            .map(|r| r.parse().unwrap())
            .collect();
        assert_eq!(republish.relays, Some(default_relays));
    }

    #[test]
    fn config_file_overrides_defaults() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret.hex"
            listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
            http_backend_addr = "127.0.0.1:8080"
            https_backend_addr = "127.0.0.1:8443"
            plain_http = false
            proxy_protocol = false

            [republish]
            interval_secs = 600
            cache_file = "state/pkarr-packet.cache"

            [pkarr]
            bootstrap_nodes = ["127.0.0.1:6881"]
            relays = ["https://relay.example.com"]
            "#,
        );

        let settings = home.load(Args::default()).unwrap();

        assert_eq!(
            settings.config_file,
            Some(home.config_dir().join(CONFIG_FILE_NAME))
        );
        assert_eq!(settings.secret_file, home.config_dir().join("secret.hex"));
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
            settings.https_backend_addr,
            Some("127.0.0.1:8443".parse().unwrap())
        );
        assert!(!settings.plain_http);
        assert!(!settings.send_proxy_protocol);
        let republish = settings.republish.unwrap();
        assert_eq!(republish.interval, Duration::from_secs(600));
        assert_eq!(
            republish.cache_file,
            home.config_dir().join("state/pkarr-packet.cache")
        );
        assert_eq!(
            republish.dht_bootstrap_nodes,
            Some(vec!["127.0.0.1:6881".parse().unwrap()])
        );
        assert_eq!(
            republish.relays,
            Some(vec!["https://relay.example.com".parse().unwrap()])
        );
    }

    #[test]
    fn command_line_overrides_config_file() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "from-file"
            listen_addrs = ["0.0.0.0:80"]
            http_backend_addr = "127.0.0.1:8080"
            plain_http = true
            [republish]
            interval_secs = 600
            [pkarr]
            relays = ["https://relay.example.com"]
            "#,
        );
        let args = Args {
            secret_file: Some("from-cli".into()),
            listen_addrs: vec!["127.0.0.1:9000".parse().unwrap()],
            http_backend_addr: Some("127.0.0.1:9001".parse().unwrap()),
            republish_interval_secs: Some(60),
            packet_cache_file: Some("/var/lib/proxy/pkarr-packet.cache".into()),
            pkarr_bootstrap_nodes: vec!["127.0.0.2:6881".into()],
            pkarr_relays: vec!["https://other-relay.example.com".into()],
            no_proxy_protocol: true,
            no_plain_http: true,
            ..Args::default()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(settings.secret_file, home.config_dir().join("from-cli"));
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
        let republish = settings.republish.unwrap();
        assert_eq!(republish.interval, Duration::from_secs(60));
        assert_eq!(
            republish.cache_file,
            PathBuf::from("/var/lib/proxy/pkarr-packet.cache")
        );
        assert_eq!(
            republish.dht_bootstrap_nodes,
            Some(vec!["127.0.0.2:6881".parse().unwrap()])
        );
        assert_eq!(
            republish.relays,
            Some(vec!["https://other-relay.example.com".parse().unwrap()])
        );
    }

    #[test]
    fn relative_cli_paths_resolve_against_config_dir_even_without_config_file() {
        let home = FakeHome::without_config();

        let settings = home.load(args_with_secret_file()).unwrap();

        assert_eq!(settings.secret_file, home.config_dir().join("secret"));
    }

    #[test]
    fn absolute_paths_are_kept() {
        let home = FakeHome::without_config();
        let args = Args {
            secret_file: Some("/etc/pkdns-demo/secret.hex".into()),
            ..args_with_secret_file()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(
            settings.secret_file,
            PathBuf::from("/etc/pkdns-demo/secret.hex")
        );
    }

    #[test]
    fn explicit_config_file_is_used_and_its_dir_is_the_base_dir() {
        let home = FakeHome::without_config();
        let other_dir = TempDir::new().unwrap();
        let config_file = other_dir.path().join("proxy.toml");
        fs::write(&config_file, r#"secret_file = "secret.hex""#).unwrap();
        let args = Args {
            config: Some(config_file.clone()),
            no_republish: true,
            ..Args::default()
        };

        let settings = home.load(args).unwrap();

        assert_eq!(settings.config_file, Some(config_file));
        assert_eq!(settings.secret_file, other_dir.path().join("secret.hex"));
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        let home = FakeHome::without_config();
        let args = Args {
            config: Some("/does/not/exist.toml".into()),
            ..args_with_secret_file()
        };

        let error = home.load(args).unwrap_err();

        assert!(error.to_string().contains("does not exist"), "{error}");
    }

    #[test]
    fn unknown_config_key_is_an_error() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret"
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
    fn missing_secret_file_is_an_error() {
        let home = FakeHome::without_config();

        let error = home.load(Args::default()).unwrap_err();

        assert!(
            error.to_string().contains("No secret file configured"),
            "{error}"
        );
    }

    #[test]
    fn empty_relay_list_disables_relays() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret"
            [pkarr]
            bootstrap_nodes = ["127.0.0.1:6881"]
            relays = []
            "#,
        );

        let republish = home.load(Args::default()).unwrap().republish.unwrap();

        assert_eq!(republish.relays, None);
        assert!(republish.dht_bootstrap_nodes.is_some());
    }

    #[test]
    fn no_pkarr_dht_flag_disables_dht() {
        let home = FakeHome::without_config();
        let args = Args {
            no_republish: false,
            no_pkarr_dht: true,
            ..args_with_secret_file()
        };

        let republish = home.load(args).unwrap().republish.unwrap();

        assert_eq!(republish.dht_bootstrap_nodes, None);
        assert!(republish.relays.is_some());
    }

    #[test]
    fn republishing_without_any_network_is_an_error() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret"
            [pkarr]
            bootstrap_nodes = []
            relays = []
            "#,
        );

        let error = home.load(Args::default()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Republishing needs the DHT or at least one relay"),
            "{error}"
        );
    }

    #[test]
    fn no_network_is_fine_when_republishing_is_disabled() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret"
            [republish]
            enabled = false
            [pkarr]
            bootstrap_nodes = []
            relays = []
            "#,
        );

        let settings = home.load(Args::default()).unwrap();

        assert!(settings.republish.is_none());
    }

    #[test]
    fn invalid_relay_url_is_an_error() {
        let home = FakeHome::without_config();
        let args = Args {
            no_republish: false,
            no_pkarr_dht: true,
            pkarr_relays: vec!["not a url".into()],
            ..args_with_secret_file()
        };

        let error = home.load(args).unwrap_err();

        assert!(
            error.to_string().contains("Invalid pkarr relay URL"),
            "{error}"
        );
    }

    #[test]
    fn connection_limits_merge_config_and_command_line() {
        let home = FakeHome::with_config(
            r#"
            secret_file = "secret"
            max_connections = 50
            handshake_timeout_secs = 7
            backend_timeout_secs = 8
            idle_timeout_secs = 90
        "#,
        );
        let args = Args {
            max_connections: Some(25),
            handshake_timeout_secs: Some(3),
            ..args_with_secret_file()
        };

        let limits = home.load(args).unwrap().limits;
        assert_eq!(limits.max_connections, 25);
        assert_eq!(limits.handshake_timeout, Duration::from_secs(3));
        assert_eq!(limits.backend_timeout, Duration::from_secs(8));
        assert_eq!(limits.idle_timeout, Duration::from_secs(90));
    }

    #[test]
    fn invalid_connection_limits_are_rejected() {
        for invalid in [
            "max_connections = 0",
            "handshake_timeout_secs = 0",
            "backend_timeout_secs = 0",
            "idle_timeout_secs = 0",
        ] {
            let home = FakeHome::with_config(&format!("secret_file = \"secret\"\n{invalid}\n"));
            assert!(home.load(args_with_secret_file()).is_err(), "{invalid}");
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
}
