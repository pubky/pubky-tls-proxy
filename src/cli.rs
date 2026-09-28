//! Command line arguments.
//!
//! Every setting can also come from the config file (see `config.rs`). That's why most
//! arguments are optional here: an absent flag means "use the config file or the default".

use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

/// A proxy that terminates Pubky TLS with a pkarr secret key and routes all other HTTP(S)
/// traffic to a regular web server such as nginx.
///
/// Plain HTTP and decrypted Pubky TLS go to the HTTP backend. Regular HTTPS is passed through
/// to the HTTPS backend without decrypting it. The pkarr packet of the public key is
/// republished periodically.
///
/// Settings are read from ~/.pubky-tls-proxy/config.toml if it exists. Command line
/// arguments override the config file. Relative paths are resolved against the directory
/// of the config file, both in the file and on the command line.
#[derive(Parser, Debug, Default)]
#[command(author, version, about)]
pub struct Args {
    /// Config file to use instead of ~/.pubky-tls-proxy/config.toml. Must exist.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// File containing the pkarr secret key in HEX format.
    /// Relative to the config file's directory.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,

    /// Address to listen on. Can be repeated (e.g. for ports 80 and 443). [default: 0.0.0.0:8443]
    #[arg(long = "listen-addr", value_name = "ADDR")]
    pub listen_addrs: Vec<SocketAddr>,

    /// Backend for plain HTTP and decrypted Pubky TLS traffic. [default: 127.0.0.1:6286]
    #[arg(long, alias = "backend-addr", value_name = "ADDR")]
    pub http_backend_addr: Option<SocketAddr>,

    /// Backend for regular HTTPS traffic, which is forwarded still encrypted.
    /// If not set, regular HTTPS connections are closed.
    #[arg(long, value_name = "ADDR")]
    pub https_backend_addr: Option<SocketAddr>,

    /// Reject incoming plain HTTP without forwarding it to the HTTP backend.
    #[arg(long)]
    pub no_plain_http: bool,

    /// Don't send a PROXY protocol v1 header to the backends.
    #[arg(long)]
    pub no_proxy_protocol: bool,

    /// Don't republish the pkarr packet.
    #[arg(long)]
    pub no_republish: bool,

    /// Seconds between two republish runs. [default: 3600]
    #[arg(long, value_name = "SECONDS")]
    pub republish_interval_secs: Option<u64>,

    /// File that keeps a copy of the pkarr packet, to republish it even if it disappeared
    /// from the DHT and the relays. Relative to the config file's directory.
    /// [default: pkarr-packet.cache]
    #[arg(long, value_name = "FILE")]
    pub packet_cache_file: Option<PathBuf>,

    /// Mainline DHT bootstrap node. Can be repeated. Replaces the default bootstrap nodes.
    #[arg(
        long = "pkarr-bootstrap-node",
        value_name = "HOST:PORT",
        conflicts_with = "no_pkarr_dht"
    )]
    pub pkarr_bootstrap_nodes: Vec<String>,

    /// Pkarr relay URL. Can be repeated. Replaces the default relays.
    #[arg(
        long = "pkarr-relay",
        value_name = "URL",
        conflicts_with = "no_pkarr_relays"
    )]
    pub pkarr_relays: Vec<String>,

    /// Don't use the mainline DHT for republishing.
    #[arg(long)]
    pub no_pkarr_dht: bool,

    /// Don't use pkarr relays for republishing.
    #[arg(long)]
    pub no_pkarr_relays: bool,
}
