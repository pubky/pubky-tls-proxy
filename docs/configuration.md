# Configuration

Every setting can be given on the command line or in a config file. Command line
arguments override the config file, and the config file overrides the defaults.
Run `pubky-tls-proxy --help` for all arguments.

```bash
pubky-tls-proxy [--config <FILE>] [--secret-file <FILE>] [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--https-backend-addr <ADDR>] [--no-plain-http] [--no-proxy-protocol] ...
```

## Arguments

- `--config`: Config file to use instead of `~/.pubky-tls-proxy/config.toml`. Must exist.
- `--secret-file`: Secret key file containing 32 bytes as 64 hexadecimal characters. Defaults to `secret` in the config directory. Created automatically if missing.
- `--listen-addr`: Address to listen on. Can be repeated, e.g. for ports 80 and 443 [default: 0.0.0.0:8443].
- `--http-backend-addr`: Backend for plain HTTP and decrypted raw public key TLS traffic [default: 127.0.0.1:6286]. `--backend-addr` still works as an alias.
- `--https-backend-addr`: Backend for certificate-based HTTPS traffic. If it isn't set, certificate-based HTTPS connections are closed.
- `--no-plain-http`: Close incoming plain HTTP connections without contacting the backend. Decrypted raw public key TLS still goes to the HTTP backend. Plain HTTP is enabled by default.
- `--no-proxy-protocol`: Don't send a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header to the backends. See [PROXY protocol](#proxy-protocol).
- `--max-connections`: Maximum active client connections across all listen addresses [default: 1024]. When full, new connections are closed immediately.
- `--handshake-timeout-secs`: Maximum time to complete a raw public key TLS handshake after traffic detection [default: 10].
- `--backend-timeout-secs`: Maximum time to connect to a backend and send its PROXY protocol header [default: 10].
- `--idle-timeout-secs`: Close an established connection after this many seconds without data transfer in either direction [default: 300]. Active connections have no maximum lifetime.
- `--no-republish`: Disable PKARR publishing and republishing.
- `--republish-interval-secs`: Seconds between two republish runs [default: 3600].
- `--packet-cache-file`: Where the [packet cache](#packet-cache) is kept [default: `pkarr-packet.cache` in the config directory].
- `--pkarr-bootstrap-node`: Mainline DHT bootstrap node (`host:port`). Can be repeated. Replaces the default bootstrap nodes.
- `--pkarr-relay`: PKARR relay URL. Can be repeated. Replaces the default relays.
- `--no-pkarr-dht` / `--no-pkarr-relays`: Don't publish or republish to the DHT / to relays.
- `--dns-records-file`: Use this TOML file as the complete DNS record set for the PKARR packet. The default `dns-records.toml` beside the config is used if present.
- `--check`: Validate configuration, DNS records, and an existing secret key offline, without creating a key, starting listeners, or publishing. A missing secret key is reported as pending generation at startup; malformed or unreadable secret key files are errors.

Relative paths are resolved against the directory of the config file, both in the file and on the command line. By default that's `~/.pubky-tls-proxy/`. So `--secret-file secret` means `~/.pubky-tls-proxy/secret`.

## Config file

On first run, the proxy creates a commented starter file at
`~/.pubky-tls-proxy/config.toml`. Edit it to customize the proxy; it is never
overwritten on later starts. The proxy reads it automatically. Use `--config <FILE>`
to read another, existing file instead (no file is created at that path). All keys
are optional. Unknown keys are an error. The generated file is also available as
[`config.example.toml`](../config.example.toml). This example shows the defaults:

```toml
# Optional. Created if missing. Relative to this file's directory.
secret_file = "secret"
listen_addrs = ["0.0.0.0:8443"]
http_backend_addr = "127.0.0.1:6286"
# https_backend_addr = "127.0.0.1:6443"   # not set: certificate-based HTTPS is rejected
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
# records_file = "dns-records.toml" # optional; auto-detected if present
# A list replaces the defaults. An empty list disables that network.
bootstrap_nodes = ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881"]
relays = ["https://pkarr.pubky.app", "https://pkarr.pubky.org"]
```

The command line can only switch things off (`--no-...`). If the config file says `proxy_protocol = false`, no flag turns it back on.

To dedicate a listen port to raw public key TLS, set `plain_http = false` and leave `https_backend_addr` unset. In a shared-port setup with HTTP redirects or Let's Encrypt HTTP-01 challenges, keep plain HTTP enabled and handle those requests in the backend.

## Publishing and republishing the PKARR packet

DHT nodes and relays forget PKARR packets after a while unless they are published again. The proxy therefore republishes the PKARR packet for its Public Key Domain: right after startup, then every `interval_secs`.

In **external-packet mode** (without a DNS records file), each run resolves the most recent PKARR packet from the DHT and the relays and republishes it **unchanged**: same records, signature and timestamp. You must publish that packet once with another tool. If no packet is found, neither on the networks nor in the [packet cache](#packet-cache), a warning is logged.

In **local-records mode**, the proxy builds a PKARR packet from the [DNS records file](#publishing-dns-records), signs and publishes it, and checks the file for changes every three seconds. `enabled = false` or `--no-republish` disables both modes.

Each network is published to separately. A failed publish is retried after 1 and 5 minutes, then logged as an error. The next run starts at the next interval.

DHT bootstrap nodes are resolved once at startup. Nodes without an IPv4 address are skipped with a warning.

If the host's network blocks Mainline DHT traffic (UDP), e.g. through a restrictive cloud firewall, set `bootstrap_nodes = []` in the config file or pass `--no-pkarr-dht`. The proxy then publishes and republishes through the relays only, and the relays publish the packet to the DHT themselves.

## Packet cache

In external-packet mode, the proxy keeps a copy of the most recent PKARR packet in `pkarr-packet.cache`, next to the config file by default. If the packet ever disappears from the DHT and the relays, the proxy republishes this copy instead. It also does so if the networks only return an older packet than the cached one.

- The cache is always on while republishing is on. Change its location with `cache_file` or `--packet-cache-file`. The directory must be writable by the proxy.
- The file holds one PKARR packet in the `pkarr` crate's `SignedPacket::serialize` format. In external-packet mode it's only replaced by a newer packet from the networks.
- On every run the file is checked: a packet for another public key, with an invalid signature, or a corrupt file is ignored with a warning.

In local-records mode the cache is written before publishing but is never used as the source of records. A restart builds and signs a new PKARR packet from the current DNS records file. An invalid edit or a temporarily missing file leaves the last valid packet in memory until the file is fixed.

## Publishing DNS records

Place `dns-records.toml` next to `config.toml` (or specify `[pkarr] records_file = "path/to/file.toml"` or `--dns-records-file`). An explicitly selected file must exist. The file is authoritative: removing a record removes it from the next published packet; records from the network are never merged into it.

```toml
default_ttl = 300

[[records]]
name = "@"
type = "A"
address = "203.0.113.10" # replace with your server's public IPv4 address

[[records]]
name = "@"
type = "HTTPS"
priority = 1
target = "."
port = 8443 # use 443 for a shared-port setup

[[records]]
name = "_demo"
type = "TXT"
text = "hello"
```

Owner `name` is relative to the Public Key Domain (`@` is the apex). `target` is a literal DNS name: `.` means the current host in an HTTPS/SVCB service record; use a fully qualified DNS name with a trailing dot for external CNAME or service targets. Supported `type` values: `A`, `AAAA`, `CNAME`, `TXT`, `HTTPS`, `SVCB`. For `HTTPS` and `SVCB`, set `priority` and `target`; optional service fields are `port`, `alpn = ["h2", "http/1.1"]`, `no_default_alpn = true`, `ipv4hint = ["203.0.113.10"]`, and `ipv6hint = ["2001:db8::1"]`. Priority 0 is alias mode and cannot have service fields. `ttl` on a record overrides `default_ttl` (300 seconds). TTLs must be positive; a port must be nonzero. The encoded DNS payload must fit PKARR's 1000-byte DNS packet limit.

Run `pubky-tls-proxy --config /etc/pubky-tls-proxy/config.toml --check` before restarting. Invalid files at startup fail with a diagnostic; invalid live edits leave the last valid packet in place and are logged until corrected. Edits to comments, spacing, and record order do not cause a new publication. Valid changes publish promptly; clients may still cache old records until their TTL expires. If another writer uses the same secret key, the proxy tries to publish a newer PKARR packet built from the local DNS records file and logs repeated conflicts. To return to external-packet mode, remove the default file and restart (or remove an explicitly configured `records_file` setting as well).

## PROXY protocol

The backend sees every connection coming from the proxy. So that it still knows the real client address, the proxy starts each backend connection with a PROXY protocol v1 header, e.g. `PROXY TCP4 203.0.113.7 10.0.0.1 51000 443`.

This is **on by default**. The backend must be configured to expect the header (in nginx: `listen ... proxy_protocol;`). If the backend doesn't support it, pass `--no-proxy-protocol`.

## Logging

The proxy logs to stdout at `info` level. Set `RUST_LOG` for more detail, e.g. `RUST_LOG=pubky_tls_proxy=debug`. Clients that disconnect or stay silent are only logged at `debug` level.

## Shutdown

On Unix, both Ctrl+C (SIGINT) and SIGTERM run the application's shutdown handler.
This includes the SIGTERM sent by systemd and container runtimes when stopping the service.
Other platforms use Ctrl+C.

The proxy stops accepting connections and stops packet republishing. Active connections
have up to five seconds to finish. If any remain, they are cancelled and the process exits
with a shutdown timeout error.

## Running directly in front of a Pubky homeserver

Without nginx, the proxy can terminate raw public key TLS and forward decrypted HTTP straight to a homeserver. A homeserver doesn't understand the PROXY protocol, so turn it off:

```bash
pubky-tls-proxy --secret-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

## Creating a secret key

The proxy generates and saves a secret key automatically when the file is missing, creating
parent directories as needed. By default it uses `~/.pubky-tls-proxy/secret`; set
`--secret-file` or `secret_file` to choose another path. With `--config`, the default
key file is saved beside that config file. The process needs write access to the directory.

Subsequent starts reuse the same key. Empty, malformed, or unreadable files cause an
error and are never replaced. New secret key files have owner-only permissions (`0600`)
on Unix. Back up the secret key to retain control of your Public Key Domain, and keep it private.
Generating a replacement key creates a different Public Key Domain.

To start with an automatically generated key:

```bash
pubky-tls-proxy
```

The startup log shows the public key and the generated secret key file's location, never the
secret key itself. To make a new Public Key Domain discoverable, create a [DNS records file](#publishing-dns-records)
with an `A` record for the server and an `HTTPS` record for the proxy's listen port.
That's port 8443 in the [recommended nginx guide](guides/nginx-letsencrypt.md),
or 443 in the [shared-port guide](guides/nginx-letsencrypt-shared-port.md).
