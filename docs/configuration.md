# Configuration

Every setting can be given on the command line or in a config file. Command line
arguments override the config file, and the config file overrides the defaults.
Run `pubky-tls-proxy --help` for all arguments.

Version 0.4.0 renames several options and consolidates PKARR settings. See the
[migration guide](configuration-migration.md) when upgrading from 0.3.x.

```bash
pubky-tls-proxy [--config <FILE>] [--secret-key-file <FILE>] [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--tls-passthrough-backend-addr <ADDR>] [--no-plain-http] [--no-proxy-protocol] ...
```

## Arguments

- `--config`: Config file to use instead of `~/.pubky-tls-proxy/config.toml`. Must exist.
- `--secret-key-file`: Required secret key file containing 32 bytes as 64 hexadecimal characters. Defaults to `secret` in the config directory. Only `init` creates it.
- `--listen-addr`: Address to listen on. Can be repeated, e.g. for ports 80 and 443 [default: 0.0.0.0:8443].
- `--http-backend-addr`: Backend for plain HTTP and decrypted raw public key TLS traffic [default: 127.0.0.1:6286].
- `--tls-passthrough-backend-addr`: Backend for encrypted TLS traffic, including certificate-based HTTPS and unparseable TLS handshakes. If it isn't set, TLS passthrough connections are closed.
- `--no-plain-http`: Close incoming plain HTTP connections without contacting the backend. Decrypted raw public key TLS still goes to the HTTP backend. Plain HTTP is enabled by default.
- `--no-proxy-protocol`: Don't send a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header to the backends. See [PROXY protocol](#proxy-protocol).
- `--max-connections`: Maximum active client connections across all listen addresses [default: 1024]. When full, new connections are closed immediately.
- `--rpk-handshake-timeout-secs`: Maximum time to complete a raw public key (RPK) TLS handshake after traffic detection [default: 10].
- `--backend-setup-timeout-secs`: Maximum time to connect to a backend and send its PROXY protocol header [default: 10].
- `--idle-timeout-secs`: Close an established connection after this many seconds without data transfer in either direction [default: 300]. Active connections have no maximum lifetime.
- `--no-pkarr-publish`: Disable PKARR publishing and republishing.
- `--pkarr-mode`: `local-records` (default) or `external-packet`. CLI overrides `[pkarr] mode`.
- `--pkarr-republish-interval-secs`: Seconds between two republish runs [default: 3600].
- `--pkarr-packet-cache-file`: Where the [packet cache](#packet-cache) is kept [default: `pkarr-packet.cache` in the config directory].
- `--pkarr-dht-bootstrap-node`: Mainline DHT bootstrap node (`host:port`). Can be repeated. Replaces the default bootstrap nodes.
- `--pkarr-relay-url`: PKARR relay URL. Can be repeated. Replaces the default relays.
- `--no-pkarr-dht` / `--no-pkarr-relays`: Don't publish or republish to the DHT / to relays.
- `--dns-records-file`: Use this TOML file as the complete DNS record set for the PKARR packet. Local-records mode requires it; the default is `dns-records.toml` beside the config. Conflicts with external-packet mode.
- `--check`: Validate the same required files as startup, offline, without creating files, starting listeners, or publishing. Missing or invalid required files are errors. Disabled publishing and external-packet mode need no DNS records file.

Relative paths are resolved against the directory of the config file, both in the file and on the command line. By default that's `~/.pubky-tls-proxy/`. So `--secret-key-file secret` means `~/.pubky-tls-proxy/secret`.

## Config file

Run `init` to create a commented starter file at
`~/.pubky-tls-proxy/config.toml`. Edit it to customize the proxy; startup and `--check`
require it and never create files. Use `--config <FILE>`
to read another, existing file instead. All keys
are optional. Unknown keys are an error. The generated file is also available as
[`config.example.toml`](../config.example.toml). This example shows the defaults:

```toml
# Required file. Created by init. Relative to this file's directory.
secret_key_file = "secret"
listen_addrs = ["0.0.0.0:8443"]
http_backend_addr = "127.0.0.1:6286"
# tls_passthrough_backend_addr = "127.0.0.1:6443" # not set: TLS passthrough is rejected
plain_http = true                          # false: reject incoming plain HTTP
proxy_protocol = true
max_connections = 1024
rpk_handshake_timeout_secs = 10
backend_setup_timeout_secs = 10
idle_timeout_secs = 300

[pkarr]
publish = true
mode = "local-records"
dns_records_file = "dns-records.toml" # required in local-records mode
republish_interval_secs = 3600
packet_cache_file = "pkarr-packet.cache"
# A list replaces the defaults. An empty list disables that network.
dht_bootstrap_nodes = ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881"]
relay_urls = ["https://pkarr.pubky.app", "https://pkarr.pubky.org"]
```

The command line can only switch things off (`--no-...`). If the config file says `proxy_protocol = false`, no flag turns it back on.

To dedicate a listen port to raw public key TLS, set `plain_http = false` and leave `tls_passthrough_backend_addr` unset. In a shared-port setup with HTTP redirects or Let's Encrypt HTTP-01 challenges, keep plain HTTP enabled and handle those requests in the backend.

## Initialization

`init` is available in the next release; the existing manual setup instructions also
work with v0.4.0.

```sh
pubky-tls-proxy init
```

Setup writes starter files without prompts or a terminal requirement. It prepares
`config.toml`, `secret`, and `dns-records.toml` in `~/.pubky-tls-proxy/`, using a
detected public IPv4 and port `8443` for A + HTTPS records. These defaults suit a
typical public-server setup. It never starts listeners, contacts PKARR networks,
or publishes records. Review the IP, port, and backend settings before starting.

Address detection queries `https://api.ipify.org`, with
`https://ipv4.icanhazip.com` as a fallback, using direct IPv4 HTTPS connections.
Each request has a three-second timeout, with a six-second overall limit.
The detected address may need editing: outbound NAT, CGNAT, and load balancers may use a
different address from the one clients should connect to. Detection does not test
inbound reachability. If detection fails, no setup files are created; rerun with
`--public-ip YOUR_PUBLIC_IPV4`. `--public-ip` skips
detection. Ensure the advertised TCP port reaches the proxy.

To override the starter address or port:

```sh
pubky-tls-proxy init --public-ip YOUR_PUBLIC_IPV4
# Shared-port deployment:
pubky-tls-proxy init --public-ip YOUR_PUBLIC_IPV4 --port 443
# Custom configuration directory:
pubky-tls-proxy init --directory /path/to/proxy --public-ip YOUR_PUBLIC_IPV4
```

Replace `YOUR_PUBLIC_IPV4` with a globally routable IPv4 address. The same prompt-free
flow works in scripts; an explicit address avoids relying on an external detection service.
`--port` changes the advertised port, not the listeners in `config.toml`.
Edit listener and backend settings to match your deployment before starting.

Existing files are validated and never overwritten. If `config.toml` already
selects custom secret or DNS records paths, setup uses those paths, resolving them
against the configuration directory. Unlike normal startup, `init` can create a
missing explicitly selected DNS records file. Rerunning setup fills in missing
files; `--public-ip` and `--port` do not modify an existing records file. Invalid
existing files require manual correction. A write failure can leave some files
created; rerun after fixing the problem.
For an existing external-packet configuration or disabled publishing, `init`
prepares only the config and key; it skips IP detection and local records.

Review the records, then validate and start:

```sh
pubky-tls-proxy --check
pubky-tls-proxy
```

For a custom directory, pass `--config /path/to/proxy/config.toml` to both commands.
Normal startup publishes the reviewed file unless publishing is disabled. Changes
to the address require editing `dns-records.toml`; setup does not implement dynamic
DNS. Missing required files make startup fail with instructions to run `init`.
External-packet republishing must be selected explicitly.

## Publishing and republishing the PKARR packet

DHT nodes and relays forget PKARR packets after a while unless they are published again. The proxy therefore republishes the PKARR packet for its Public Key Domain: right after startup, then every `republish_interval_secs`.

In **external-packet mode** (`[pkarr] mode = "external-packet"` or `--pkarr-mode external-packet`), each run resolves the most recent PKARR packet from the DHT and the relays and republishes it **unchanged**: same records, signature and timestamp. You must publish that packet once with another tool. If no packet is found, neither on the networks nor in the [packet cache](#packet-cache), a warning is logged. An existing default DNS records file is ignored; an explicit `dns_records_file` conflicts with this mode.

In **local-records mode** (the default), the proxy requires the [DNS records file](#publishing-dns-records), signs and publishes it, and checks the file for changes every three seconds. `[pkarr] publish = false` or `--no-pkarr-publish` disables both modes and removes the DNS records file requirement for startup and `--check`.

Each network is published to separately. A failed publish is retried after 1 and 5 minutes, then logged as an error. The next run starts at the next interval.

DHT bootstrap nodes are resolved once at startup. Nodes without an IPv4 address are skipped with a warning.

If the host's network blocks Mainline DHT traffic (UDP), e.g. through a restrictive cloud firewall, set `[pkarr] dht_bootstrap_nodes = []` in the config file or pass `--no-pkarr-dht`. The proxy then publishes and republishes through the relays only, and the relays publish the packet to the DHT themselves.

## Packet cache

In external-packet mode, the proxy keeps a copy of the most recent PKARR packet in `pkarr-packet.cache`, next to the config file by default. If the packet ever disappears from the DHT and the relays, the proxy republishes this copy instead. It also does so if the networks only return an older packet than the cached one.

- The cache is always on while publishing is on. Change its location with `[pkarr] packet_cache_file` or `--pkarr-packet-cache-file`. The directory must be writable by the proxy.
- The file holds one PKARR packet in the `pkarr` crate's `SignedPacket::serialize` format. In external-packet mode it's only replaced by a newer packet from the networks.
- On every run the file is checked: a packet for another public key, with an invalid signature, or a corrupt file is ignored with a warning.

In local-records mode the cache is written before publishing but is never used as the source of records. A restart builds and signs a new PKARR packet from the current DNS records file. An invalid edit or a temporarily missing file leaves the last valid packet in memory until the file is fixed.

## Publishing DNS records

Place `dns-records.toml` next to `config.toml` (or specify `[pkarr] dns_records_file = "path/to/file.toml"` or `--dns-records-file`). An explicitly selected file must exist. The file is authoritative: removing a record removes it from the next published packet; records from the network are never merged into it.

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

Run `pubky-tls-proxy --config /etc/pubky-tls-proxy/config.toml --check` before restarting. Invalid files at startup fail with a diagnostic; invalid live edits leave the last valid packet in place and are logged until corrected. Edits to comments, spacing, and record order do not cause a new publication. Valid changes publish promptly; clients may still cache old records until their TTL expires. If another writer uses the same secret key, the proxy tries to publish a newer PKARR packet built from the local DNS records file and logs repeated conflicts. To return to external-packet mode, set `[pkarr] mode = "external-packet"`, remove any explicitly configured `dns_records_file`, and restart. Deleting a records file alone never changes the publishing mode.

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
pubky-tls-proxy --secret-key-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

## Creating a secret key

`init` generates and saves a secret key when missing, creating
parent directories as needed. Startup and `--check` require the saved key. By default it uses `~/.pubky-tls-proxy/secret`; set
`secret_key_file` in an existing config before running `init` to choose another setup
path, or use `--secret-key-file` to select an existing key at runtime. With `--config`,
the default key file must exist beside that config file. Setup needs write access to the directory.

Subsequent starts reuse the same key. Empty, malformed, or unreadable files cause an
error and are never replaced. New secret key files have owner-only permissions (`0600`)
on Unix. Back up the secret key to retain control of your Public Key Domain, and keep it private.
Generating a replacement key creates a different Public Key Domain.

To prepare a generated key before startup:

```bash
pubky-tls-proxy init
pubky-tls-proxy --check
pubky-tls-proxy
```

The setup log shows the public key and the generated secret key file's location, never the
secret key itself. To make a new Public Key Domain discoverable, create a [DNS records file](#publishing-dns-records)
with an `A` record for the server and an `HTTPS` record for the proxy's listen port.
That's port 8443 in the [recommended nginx guide](guides/nginx-letsencrypt.md),
or 443 in the [shared-port guide](guides/nginx-letsencrypt-shared-port.md).
