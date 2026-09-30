//! Command line arguments.
//!
//! Every setting can also come from the config file (see `config.rs`). That's why most
//! arguments are optional here: an absent flag means "use the config file or the default".

use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

/// A proxy that terminates raw public key TLS with a secret key and routes HTTP(S)
/// traffic to a web server such as nginx.
///
/// Plain HTTP and decrypted raw public key TLS go to the HTTP backend. Certificate-based HTTPS is passed through
/// to the HTTPS backend without decrypting it. The PKARR packet for the Public Key Domain is
/// republished periodically.
///
/// A commented ~/.pubky-tls-proxy/config.toml is created on first run. Command line
/// arguments override the config file. Relative paths are resolved against the directory
/// of the config file, both in the file and on the command line.
#[derive(Parser, Debug, Default)]
#[command(author, version, about)]
pub struct Args {
    /// Config file to use instead of ~/.pubky-tls-proxy/config.toml. Must exist.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Secret key file containing 32 bytes as 64 hexadecimal characters.
    /// Created automatically if missing. Relative to the config file's directory. [default: secret]
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,

    /// Address to listen on. Can be repeated (e.g. for ports 80 and 443). [default: 0.0.0.0:8443]
    #[arg(long = "listen-addr", value_name = "ADDR")]
    pub listen_addrs: Vec<SocketAddr>,

    /// Backend for plain HTTP and decrypted raw public key TLS traffic. [default: 127.0.0.1:6286]
    #[arg(long, alias = "backend-addr", value_name = "ADDR")]
    pub http_backend_addr: Option<SocketAddr>,

    /// Backend for certificate-based HTTPS traffic, which is forwarded still encrypted.
    /// If not set, certificate-based HTTPS connections are closed.
    #[arg(long, value_name = "ADDR")]
    pub https_backend_addr: Option<SocketAddr>,

    /// Reject incoming plain HTTP without forwarding it to the HTTP backend.
    #[arg(long)]
    pub no_plain_http: bool,

    /// Don't send a PROXY protocol v1 header to the backends.
    #[arg(long)]
    pub no_proxy_protocol: bool,

    /// Maximum simultaneous connections across all listeners. [default: 1024]
    #[arg(long)]
    pub max_connections: Option<usize>,

    /// Maximum seconds for a raw public key TLS handshake. [default: 10]
    #[arg(long)]
    pub handshake_timeout_secs: Option<u64>,

    /// Maximum seconds to connect to a backend and send its PROXY protocol header. [default: 10]
    #[arg(long)]
    pub backend_timeout_secs: Option<u64>,

    /// Seconds without transfer before closing a connection. [default: 300]
    #[arg(long)]
    pub idle_timeout_secs: Option<u64>,

    /// Disable publishing and republishing the PKARR packet.
    #[arg(long)]
    pub no_republish: bool,

    /// Seconds between two republish runs. [default: 3600]
    #[arg(long, value_name = "SECONDS")]
    pub republish_interval_secs: Option<u64>,

    /// File that keeps a copy of the PKARR packet, to republish it even if it disappeared
    /// from the DHT and the relays. Relative to the config file's directory.
    /// [default: pkarr-packet.cache]
    #[arg(long, value_name = "FILE")]
    pub packet_cache_file: Option<PathBuf>,

    /// Publish the complete DNS record set from this TOML file. Defaults to dns-records.toml
    /// beside the config file if it exists.
    #[arg(long, value_name = "FILE")]
    pub dns_records_file: Option<PathBuf>,

    /// Validate configuration, DNS records and an existing secret key offline without creating a key or listeners.
    #[arg(long)]
    pub check: bool,

    /// Mainline DHT bootstrap node. Can be repeated. Replaces the default bootstrap nodes.
    #[arg(
        long = "pkarr-bootstrap-node",
        value_name = "HOST:PORT",
        conflicts_with = "no_pkarr_dht"
    )]
    pub pkarr_bootstrap_nodes: Vec<String>,

    /// PKARR relay URL. Can be repeated. Replaces the default relays.
    #[arg(
        long = "pkarr-relay",
        value_name = "URL",
        conflicts_with = "no_pkarr_relays"
    )]
    pub pkarr_relays: Vec<String>,

    /// Don't use the Mainline DHT for publishing or republishing.
    #[arg(long)]
    pub no_pkarr_dht: bool,

    /// Don't use PKARR relays for publishing or republishing.
    #[arg(long)]
    pub no_pkarr_relays: bool,
}
