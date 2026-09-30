//! Command line arguments.
//!
//! Every setting can also come from the config file (see `config.rs`). That's why most
//! arguments are optional here: an absent flag means "use the config file or the default".

use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

/// A proxy that terminates raw public key TLS with a secret key and routes HTTP(S)
/// traffic to a web server such as nginx.
///
/// Plain HTTP and decrypted raw public key TLS go to the HTTP backend. Other TLS traffic,
/// including certificate-based HTTPS, goes to the TLS passthrough backend without decryption.
/// The PKARR packet for the Public Key Domain is republished periodically.
///
/// A commented ~/.pubky-tls-proxy/config.toml is created on first run. Command line
/// arguments override the config file. Relative paths are resolved against the directory
/// of the config file, both in the file and on the command line.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, args_conflicts_with_subcommands = true)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Config file to use instead of ~/.pubky-tls-proxy/config.toml. Must exist.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Secret key file containing 32 bytes as 64 hexadecimal characters.
    /// Created automatically if missing. Relative to the config file's directory. [default: secret]
    #[arg(long, value_name = "FILE")]
    pub secret_key_file: Option<PathBuf>,

    /// Address to listen on. Can be repeated (e.g. for ports 80 and 443). [default: 0.0.0.0:8443]
    #[arg(long = "listen-addr", value_name = "ADDR")]
    pub listen_addrs: Vec<SocketAddr>,

    /// Backend for plain HTTP and decrypted raw public key TLS traffic. [default: 127.0.0.1:6286]
    #[arg(long, value_name = "ADDR")]
    pub http_backend_addr: Option<SocketAddr>,

    /// Backend for TLS passthrough, including certificate-based HTTPS and unparseable TLS handshakes.
    /// If not set, TLS passthrough connections are closed.
    #[arg(long, value_name = "ADDR")]
    pub tls_passthrough_backend_addr: Option<SocketAddr>,

    /// Reject incoming plain HTTP without forwarding it to the HTTP backend.
    #[arg(long)]
    pub no_plain_http: bool,

    /// Don't send a PROXY protocol v1 header to the backends.
    #[arg(long)]
    pub no_proxy_protocol: bool,

    /// Maximum simultaneous connections across all listeners. [default: 1024]
    #[arg(long)]
    pub max_connections: Option<usize>,

    /// Maximum seconds for a raw public key (RPK) TLS handshake after traffic detection. [default: 10]
    #[arg(long)]
    pub rpk_handshake_timeout_secs: Option<u64>,

    /// Maximum seconds to connect to a backend and send its PROXY protocol header. [default: 10]
    #[arg(long)]
    pub backend_setup_timeout_secs: Option<u64>,

    /// Seconds without transfer before closing a connection. [default: 300]
    #[arg(long)]
    pub idle_timeout_secs: Option<u64>,

    /// Disable publishing and republishing the PKARR packet.
    #[arg(long)]
    pub no_pkarr_publish: bool,

    /// Seconds between two republish runs. [default: 3600]
    #[arg(long, value_name = "SECONDS")]
    pub pkarr_republish_interval_secs: Option<u64>,

    /// File that keeps a copy of the PKARR packet, to republish it even if it disappeared
    /// from the DHT and the relays. Relative to the config file's directory.
    /// [default: pkarr-packet.cache]
    #[arg(long, value_name = "FILE")]
    pub pkarr_packet_cache_file: Option<PathBuf>,

    /// Publish the complete DNS record set from this TOML file. Defaults to dns-records.toml
    /// beside the config file if it exists.
    #[arg(long, value_name = "FILE")]
    pub dns_records_file: Option<PathBuf>,

    /// Validate configuration, DNS records and an existing secret key offline without creating a key or listeners.
    #[arg(long)]
    pub check: bool,

    /// Mainline DHT bootstrap node. Can be repeated. Replaces the default bootstrap nodes.
    #[arg(
        long = "pkarr-dht-bootstrap-node",
        value_name = "HOST:PORT",
        conflicts_with = "no_pkarr_dht"
    )]
    pub pkarr_dht_bootstrap_nodes: Vec<String>,

    /// PKARR relay URL. Can be repeated. Replaces the default relays.
    #[arg(
        long = "pkarr-relay-url",
        value_name = "URL",
        conflicts_with = "no_pkarr_relays"
    )]
    pub pkarr_relay_urls: Vec<String>,

    /// Don't use the Mainline DHT for publishing or republishing.
    #[arg(long)]
    pub no_pkarr_dht: bool,

    /// Don't use PKARR relays for publishing or republishing.
    #[arg(long)]
    pub no_pkarr_relays: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Prepare configuration, a secret key and DNS records without starting or publishing.
    Init(crate::init::InitArgs),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn canonical_options_parse_with_repeatable_network_settings() {
        let args = Args::try_parse_from([
            "pubky-tls-proxy",
            "--secret-key-file",
            "key.hex",
            "--tls-passthrough-backend-addr",
            "127.0.0.1:9443",
            "--rpk-handshake-timeout-secs",
            "3",
            "--backend-setup-timeout-secs",
            "4",
            "--pkarr-republish-interval-secs",
            "60",
            "--pkarr-packet-cache-file",
            "packet.cache",
            "--dns-records-file",
            "records.toml",
            "--pkarr-dht-bootstrap-node",
            "127.0.0.1:6881",
            "--pkarr-dht-bootstrap-node",
            "127.0.0.2:6881",
            "--pkarr-relay-url",
            "https://relay.example.com",
            "--pkarr-relay-url",
            "https://other.example.com",
        ])
        .unwrap();
        assert_eq!(args.secret_key_file, Some("key.hex".into()));
        assert_eq!(
            args.tls_passthrough_backend_addr,
            Some("127.0.0.1:9443".parse().unwrap())
        );
        assert_eq!(args.rpk_handshake_timeout_secs, Some(3));
        assert_eq!(args.backend_setup_timeout_secs, Some(4));
        assert_eq!(args.pkarr_republish_interval_secs, Some(60));
        assert_eq!(args.pkarr_packet_cache_file, Some("packet.cache".into()));
        assert_eq!(args.dns_records_file, Some("records.toml".into()));
        assert_eq!(
            args.pkarr_dht_bootstrap_nodes,
            ["127.0.0.1:6881", "127.0.0.2:6881"]
        );
        assert_eq!(
            args.pkarr_relay_urls,
            ["https://relay.example.com", "https://other.example.com"]
        );
    }

    #[test]
    fn removed_options_are_rejected() {
        for option in [
            "--secret-file",
            "--no-republish",
            "--republish-interval-secs",
            "--packet-cache-file",
            "--pkarr-bootstrap-node",
            "--pkarr-relay",
            "--handshake-timeout-secs",
            "--backend-timeout-secs",
            "--https-backend-addr",
            "--backend-addr",
        ] {
            let error = Args::try_parse_from(["pubky-tls-proxy", option]).unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::UnknownArgument,
                "{option}: {error}"
            );
        }
    }

    #[test]
    fn network_options_conflict_with_disabling_the_same_network() {
        for (option, value, disable) in [
            (
                "--pkarr-dht-bootstrap-node",
                "127.0.0.1:6881",
                "--no-pkarr-dht",
            ),
            (
                "--pkarr-relay-url",
                "https://relay.example.com",
                "--no-pkarr-relays",
            ),
        ] {
            let error =
                Args::try_parse_from(["pubky-tls-proxy", option, value, disable]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{error}");
        }
        assert!(
            Args::try_parse_from(["pubky-tls-proxy", "--no-pkarr-publish"])
                .unwrap()
                .no_pkarr_publish
        );
    }
}
