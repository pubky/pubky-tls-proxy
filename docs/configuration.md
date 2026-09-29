# Configuration

Every setting can be given on the command line or in a config file. Command line
arguments override the config file, and the config file overrides the defaults.
Run `pubky-tls-proxy --help` for all arguments.

```bash
pubky-tls-proxy [--config <FILE>] [--secret-file <FILE>] [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--https-backend-addr <ADDR>] [--no-plain-http] [--no-proxy-protocol] ...
```

## Arguments

- `--config`: Config file to use instead of `~/.pubky-tls-proxy/config.toml`. Must exist.
- `--secret-file`: File containing the pubky secret in HEX format (32 bytes/64 hex characters). Required, here or in the config file.
- `--listen-addr`: Address to listen on. Can be repeated, e.g. for ports 80 and 443 [default: 0.0.0.0:8443].
- `--http-backend-addr`: Backend for plain HTTP and decrypted Pubky TLS traffic [default: 127.0.0.1:6286]. `--backend-addr` still works as an alias.
- `--https-backend-addr`: Backend for regular HTTPS traffic. If it isn't set, regular HTTPS connections are closed.
- `--no-plain-http`: Close incoming plain HTTP connections without contacting the backend. Decrypted Pubky TLS still goes to the HTTP backend. Plain HTTP is enabled by default.
- `--no-proxy-protocol`: Don't send a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header to the backends. See [PROXY protocol](#proxy-protocol).
- `--max-connections`: Maximum active client connections across all listen addresses [default: 1024]. When full, new connections are closed immediately.
- `--handshake-timeout-secs`: Maximum time to complete a Pubky TLS handshake after traffic detection [default: 10].
- `--backend-timeout-secs`: Maximum time to connect to a backend and send its PROXY header [default: 10].
- `--idle-timeout-secs`: Close an established connection after this many seconds without data transfer in either direction [default: 300]. Active connections have no maximum lifetime.
- `--no-republish`: Don't [republish](#republishing-the-pkarr-packet) the pkarr packet.
- `--republish-interval-secs`: Seconds between two republish runs [default: 3600].
- `--packet-cache-file`: Where the [packet cache](#packet-cache) is kept [default: `pkarr-packet.cache` in the config directory].
- `--pkarr-bootstrap-node`: Mainline DHT bootstrap node (`host:port`). Can be repeated. Replaces the default bootstrap nodes.
- `--pkarr-relay`: Pkarr relay URL. Can be repeated. Replaces the default relays.
- `--no-pkarr-dht` / `--no-pkarr-relays`: Don't republish to the DHT / to relays.

Relative paths are resolved against the directory of the config file, both in the file and on the command line. By default that's `~/.pubky-tls-proxy/`, even if no config file exists there. So `--secret-file secret` means `~/.pubky-tls-proxy/secret`.

## Config file

`~/.pubky-tls-proxy/config.toml` is read automatically if it exists. Use `--config <FILE>` to read another file instead. All keys are optional. Unknown keys are an error. This example shows the defaults:

```toml
# Required, here or with --secret-file. Relative to this file's directory.
secret_file = "secret"
listen_addrs = ["0.0.0.0:8443"]
http_backend_addr = "127.0.0.1:6286"
# https_backend_addr = "127.0.0.1:6443"   # not set: regular HTTPS is rejected
plain_http = true                          # false: reject incoming plain HTTP
proxy_protocol = true
max_connections = 1024
handshake_timeout_secs = 10
backend_timeout_secs = 10
idle_timeout_secs = 300

[republish]
enabled = true
interval_secs = 3600
cache_file = "pkarr-packet.cache"

[pkarr]
# A list replaces the defaults. An empty list disables that network.
bootstrap_nodes = ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881"]
relays = ["https://pkarr.pubky.app", "https://pkarr.pubky.org"]
```

The command line can only switch things off (`--no-...`). If the config file says `proxy_protocol = false`, no flag turns it back on.

To dedicate a listen port to Pubky TLS, set `plain_http = false` and leave `https_backend_addr` unset. In a shared-port setup with HTTP redirects or Let's Encrypt HTTP-01 challenges, keep plain HTTP enabled and handle those requests in the backend.

## Republishing the pkarr packet

DHT nodes and relays forget pkarr packets after a while unless they are published again. The proxy therefore republishes the packet of its public key: right after startup, then every `interval_secs`.

Each run resolves the most recent packet from the DHT and the relays and publishes it again **unchanged**: same records, signature and timestamp. The proxy never creates or re-signs a packet, so you still need to publish the packet once with another tool. If no packet is found, neither on the networks nor in the [packet cache](#packet-cache), a warning is logged.

Each network is published to separately. A failed publish is retried after 1 and 5 minutes, then logged as an error. The next run starts at the next interval.

DHT bootstrap nodes are resolved once at startup. Nodes without an IPv4 address are skipped with a warning.

If the host's network blocks mainline DHT traffic (UDP), e.g. through a restrictive cloud firewall, set `bootstrap_nodes = []` in the config file or pass `--no-pkarr-dht`. The proxy then republishes through the relays only, and the relays publish the packet to the DHT themselves.

## Packet cache

The proxy keeps a copy of the most recent packet in `pkarr-packet.cache`, next to the config file by default. If the packet ever disappears from the DHT and the relays, the proxy republishes this copy instead. It also does so if the networks only return an older packet than the cached one.

- The cache is always on while republishing is on. Change its location with `cache_file` or `--packet-cache-file`. The directory must be writable by the proxy.
- The file holds one packet in pkarr's `SignedPacket::serialize` format. It's only replaced by a newer packet from the networks.
- On every run the file is checked: a packet for another public key, with an invalid signature, or a corrupt file is ignored with a warning.

## PROXY protocol

The backend sees every connection coming from the proxy. So that it still knows the real client address, the proxy starts each backend connection with a PROXY protocol v1 header, e.g. `PROXY TCP4 203.0.113.7 10.0.0.1 51000 443`.

This is **on by default**. The backend must be configured to expect the header (in nginx: `listen ... proxy_protocol;`). If the backend doesn't support it, pass `--no-proxy-protocol`.

## Logging

The proxy logs to stdout at `info` level. Set `RUST_LOG` for more detail, e.g. `RUST_LOG=pubky_tls_proxy=debug`. Clients that disconnect or stay silent are only logged at `debug` level.

On Unix, both Ctrl+C (SIGINT) and SIGTERM run the application's shutdown handler.
This includes the SIGTERM sent by systemd and container runtimes when stopping the service.
Other platforms use Ctrl+C.

## Running directly in front of a Pubky homeserver

Without nginx, the proxy can forward Pubky TLS straight to a homeserver. A homeserver doesn't understand the PROXY protocol, so turn it off:

```bash
pubky-tls-proxy --secret-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

## Creating a secret key

To generate a new secret key:

```bash
# Generate a 32-byte random secret and save as hex
openssl rand -hex 32 > secret
```

The proxy doesn't publish a pkarr packet for a new key. Publish one with an `A` record for the server and an `HTTPS` record for the proxy's listen port before you start it. That's port 8443 in the [recommended nginx guide](guides/nginx-letsencrypt.md), or 443 in the [shared-port guide](guides/nginx-letsencrypt-shared-port.md).
