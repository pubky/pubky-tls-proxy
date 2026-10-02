# Configuration

Use this reference to configure listeners, backends, connection limits, and
PKARR publishing. For a complete deployment procedure, follow the
[separate-port nginx guide](guides/nginx-letsencrypt.md) or the
[shared-port nginx guide](guides/nginx-letsencrypt-shared-port.md).

Run [`init`](#initialization) to prepare the required files before starting the
proxy. Startup and `--check` require an existing configuration file and secret
key. Local-records mode also requires a DNS records file when publishing is
enabled.

Settings use this order of precedence:

1. Command-line arguments.
2. Values in the configuration file.
3. Built-in defaults.

The `--no-...` flags disable features. They can't enable a feature disabled in
the configuration file. For example, no flag overrides `proxy_protocol = false`
to enable the PROXY protocol.

Find the section you need:

- [Arguments](#arguments)
- [Configuration file](#config-file)
- [Initialization](#initialization)
- [PKARR publishing and republishing](#publishing-and-republishing-the-pkarr-packet)
- [Packet cache](#packet-cache)
- [DNS records](#publishing-dns-records)
- [PROXY protocol](#proxy-protocol)
- [Logging](#logging)
- [Shutdown](#shutdown)
- [Pubky homeserver setup](#running-directly-in-front-of-a-pubky-homeserver)
- [Secret keys](#creating-a-secret-key)

Run `pubky-tls-proxy --help` for the full command-line help. The following
synopsis shows common options; replace `<FILE>` with a file path and `<ADDR>`
with an IP address and port:

```bash
pubky-tls-proxy [--config <FILE>] [--secret-key-file <FILE>] [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--tls-passthrough-backend-addr <ADDR>] [--no-plain-http] [--no-proxy-protocol] ...
```

## Arguments

### Files and validation

- `--config`: Select an existing configuration file instead of
  `~/.pubky-tls-proxy/config.toml`.
- `--secret-key-file`: Select an existing secret key file containing 32 bytes
  encoded as 64 hexadecimal characters. The default is `secret` in the
  configuration directory. Only `init` creates this file.
- `--check`: Validate the same required files as startup, offline, without
  creating files, starting listeners, or publishing records. Missing or invalid
  required files cause an error. External-packet mode and disabled publishing
  don't require a DNS records file.

Relative file paths in settings are resolved against the directory containing
the configuration file, whether you set them in that file or on the command
line. The default directory is `~/.pubky-tls-proxy/`, so
`--secret-key-file secret` selects `~/.pubky-tls-proxy/secret`.

### Listeners and backends

- `--listen-addr`: Set an IP address and port to listen on. Repeat the option for
  multiple listeners, such as ports 80 and 443. The default is `0.0.0.0:8443`.
- `--http-backend-addr`: Set the backend for plain HTTP and decrypted raw public
  key TLS traffic. The default is `127.0.0.1:6286`.
- `--tls-passthrough-backend-addr`: Set the backend for encrypted TLS traffic,
  including certificate-based HTTPS and unparseable TLS handshakes. No backend
  is configured by default; without one, the proxy closes TLS passthrough
  connections.
- `--no-plain-http`: Close incoming plain HTTP connections without contacting
  the backend. Decrypted raw public key TLS traffic still reaches the HTTP
  backend. Plain HTTP is enabled by default.
- `--no-proxy-protocol`: Stop sending a PROXY protocol v1 header to backends.
  Headers are enabled by default. See [PROXY protocol](#proxy-protocol) for
  backend requirements.

### Connection limits

| Option | Default | Behavior |
|--------|---------|----------|
| `--max-connections` | `1024` | Limit active client connections across all listeners. When the limit is reached, close new connections immediately. |
| `--rpk-handshake-timeout-secs` | `10` | Limit the time to complete a raw public key (RPK) TLS handshake after traffic detection. |
| `--backend-setup-timeout-secs` | `10` | Limit the time to connect to a backend and send its PROXY protocol header. |
| `--idle-timeout-secs` | `300` | Close an established connection after this many seconds without data transfer in either direction. |

All timeout values are in seconds. Active connections have no maximum lifetime.

### PKARR publishing

[PKARR](https://github.com/pubky/pkarr) publishes signed DNS records addressed by
a public key. Use these options to select the source of records and the
publishing networks:

- `--no-pkarr-publish`: Disable both publishing and republishing.
- `--pkarr-mode`: Select `local-records` (the default) or `external-packet`.
  This option overrides `mode` in the `[pkarr]` configuration section.
- `--dns-records-file`: Select the TOML file containing the complete DNS record
  set for the PKARR packet. The default is `dns-records.toml` in the
  configuration directory. Local-records mode requires this file when publishing
  is enabled. Explicitly selecting a records file conflicts with external-packet
  mode.
- `--pkarr-republish-interval-secs`: Set the interval between republish runs in
  seconds. The default is `3600` (one hour).
- `--pkarr-packet-cache-file`: Set the [packet cache](#packet-cache) location.
  The default is `pkarr-packet.cache` in the configuration directory.
- `--pkarr-dht-bootstrap-node`: Set a Mainline DHT bootstrap node as `host:port`.
  Repeat the option for multiple nodes. The supplied list replaces the defaults.
- `--pkarr-relay-url`: Set a PKARR relay URL. Repeat the option for multiple
  relays. The supplied list replaces the defaults.
- `--no-pkarr-dht`: Disable publishing and republishing to the DHT.
- `--no-pkarr-relays`: Disable publishing and republishing to relays.

## Config file

Run `init` to create `~/.pubky-tls-proxy/config.toml`, then edit the file to match
your deployment. The commented starter file is also available as
[`config.example.toml`](../config.example.toml).

Startup and `--check` require this file and never create it. To use a different
existing file, pass `--config <FILE>`.

Every configuration key is optional. Omitted keys use their defaults; unknown
keys cause an error. The following example shows the defaults:

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

### Choose which traffic to accept

To dedicate a listen port to raw public key TLS:

- Set `plain_http = false` to reject incoming plain HTTP.
- Leave `tls_passthrough_backend_addr` unset to reject TLS passthrough connections.

For shared ports with HTTP redirects or Let's Encrypt HTTP-01 challenges, keep
plain HTTP enabled and handle those requests in the HTTP backend.

## Initialization

### Prepare the files

Run initialization as the user who will run the proxy:

```sh
pubky-tls-proxy init
```

Initialization prepares these files in `~/.pubky-tls-proxy/`:

| File | Purpose |
|------|---------|
| `config.toml` | Starter configuration. |
| `secret` | Saved secret key for TLS and PKARR packet signing. |
| `dns-records.toml` | A and HTTPS records using a detected public IPv4 address and advertised port `8443`. |

`init` works without prompts or a terminal, so you can also use it in scripts.
It doesn't start listeners, contact PKARR networks, or publish records. Review
the public IP address, advertised port, listeners, and backends before startup.

The completion summary lists the files, identifies any existing files it kept,
and shows the current HTTP backend address and DNS endpoint. It also points you
to `http_backend_addr` for backend configuration. Routine internal logs are
hidden during initialization; set `RUST_LOG=info` or `RUST_LOG=debug` for
diagnostics.

### Review the detected address

Address detection queries `https://api.ipify.org`, with
`https://ipv4.icanhazip.com` as a fallback, using direct IPv4 HTTPS connections.
Each request has a three-second timeout, with a six-second overall limit.
Detection doesn't test inbound reachability. Outbound network address
translation (NAT), carrier-grade NAT (CGNAT), or a load balancer may use an
address that differs from the one clients need. Correct the generated address
if necessary, and make sure the advertised TCP port reaches the proxy.

If detection fails, initialization creates no setup files. Rerun with an explicit
address as described below.

### Set an explicit address, port, or directory

Replace `YOUR_PUBLIC_IPV4` with your server's globally routable IPv4 address.
For the custom-directory example, replace `/path/to/proxy` with the directory
where you want to store the configuration. Run the command that matches your
deployment:

```sh
pubky-tls-proxy init --public-ip YOUR_PUBLIC_IPV4
# Shared-port deployment:
pubky-tls-proxy init --public-ip YOUR_PUBLIC_IPV4 --port 443
# Custom configuration directory:
pubky-tls-proxy init --directory /path/to/proxy --public-ip YOUR_PUBLIC_IPV4
```

`--public-ip` skips address detection, which avoids relying on an external
detection service. `--port` changes the advertised port in newly created DNS
records, not the listeners in `config.toml`. Edit the listeners and backends
before starting the proxy.

### Rerun initialization

`init` validates existing files and never overwrites them. Rerunning it creates
missing files, including an explicitly selected DNS records file. The
`--public-ip` and `--port` options don't modify an existing records file.

If `config.toml` selects custom secret key or DNS records paths, initialization
uses those paths. Relative paths are resolved against the configuration
directory.

Correct invalid existing files manually before rerunning initialization. A write
failure can leave some files created; fix the cause and rerun to create the
remaining files.

For an existing configuration with external-packet mode or disabled publishing,
`init` prepares only the configuration and secret key. It skips address
detection and local DNS records.

### Validate and start the proxy

Review the configuration and DNS records, then validate the files before starting:

```sh
pubky-tls-proxy --check
pubky-tls-proxy
```

The check should print `Configuration and DNS records are valid`. For a custom
directory, pass `--config /path/to/proxy/config.toml` to both commands, replacing
the path with your configuration file's location.

In local-records mode, startup publishes the reviewed DNS records unless
publishing is disabled. To change the advertised address later, edit
`dns-records.toml`; initialization doesn't provide dynamic DNS updates.

Missing required files cause startup to fail with instructions to run `init`.
To republish an externally managed packet, explicitly select external-packet mode.

## Publishing and republishing the PKARR packet

Mainline DHT nodes and PKARR relays eventually discard packets unless they are
published again. To keep records available for your Public Key Domain, the proxy
runs its publisher immediately after startup and then every
`republish_interval_secs`.

### Local-records mode

Local-records mode is the default. The proxy requires a
[DNS records file](#publishing-dns-records), builds a PKARR packet from its
records, signs the packet, and publishes it. It checks the file every three
seconds and publishes valid changes automatically.

### External-packet mode

Use external-packet mode if another tool manages your DNS records. Before
starting, publish a PKARR packet with that tool at least once.

To select this mode, set `mode = "external-packet"` in the `[pkarr]` section or
pass `--pkarr-mode external-packet`.

Each run resolves the most recent packet from the DHT and relays and republishes
it unchanged, with the same records, signature, and timestamp. If neither the
networks nor the [packet cache](#packet-cache) contain a packet, the proxy logs a
warning.

In this mode, the proxy ignores an existing default `dns-records.toml` file.
Explicitly setting `dns_records_file` conflicts with external-packet mode.

### Disable publishing

Set `publish = false` in the `[pkarr]` section or pass `--no-pkarr-publish`.
This disables publishing and republishing in both modes. Startup and `--check`
then don't require a DNS records file.

### Publishing networks and retries

The proxy publishes to the DHT and relays separately. If publication fails, it
retries after 1 and 5 minutes, then logs an error. The next run starts at the next
configured interval.

DHT bootstrap nodes are resolved once at startup. The proxy skips nodes without
an IPv4 address and logs a warning.

If your network blocks Mainline DHT traffic (UDP), set `dht_bootstrap_nodes = []`
in the `[pkarr]` section or pass `--no-pkarr-dht`. The proxy then uses only
relays, which publish the packet to the DHT on your behalf.

## Packet cache

The packet cache stores one PKARR packet in `pkarr-packet.cache`, in the
configuration directory by default. The cache is enabled whenever publishing is
enabled.

To change its location, set `packet_cache_file` in the `[pkarr]` section or pass
`--pkarr-packet-cache-file`. The proxy must have write access to the cache
directory.

The cache file uses the `pkarr` crate's `SignedPacket::serialize` format. On each
run, the proxy checks the file and ignores it with a warning if it is corrupt,
contains an invalid signature, or contains a packet for another public key.

Cache behavior depends on the publishing mode:

- In external-packet mode, the proxy keeps the most recent packet and replaces
  it only with a newer packet from the networks. If the DHT and relays return no
  packet, or only an older one, the proxy republishes the cached copy.
- In local-records mode, the proxy writes the cache before publishing but never
  uses it as the source of DNS records. A restart builds and signs a new packet
  from the current DNS records file. An invalid live edit or a temporarily
  missing file leaves the last valid packet in memory until you fix the file.

## Publishing DNS records

### Create the records file

Use `dns-records.toml` in the same directory as `config.toml`. To select a
different file, set `dns_records_file` in the `[pkarr]` section or pass
`--dns-records-file`. An explicitly selected file must exist before startup.

The file defines the complete record set. Removing a record removes it from the
next published packet. The proxy never merges records from the network into
this file.

The following example publishes an A record, an HTTPS record, and a TXT record.
Replace `203.0.113.10` with your server's public IPv4 address. Use port `8443`
for a separate-port deployment or `443` for a shared-port deployment:

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

### Record names and types

- `name` is relative to the Public Key Domain. Use `@` for the apex.
- `type` accepts `A`, `AAAA`, `CNAME`, `TXT`, `HTTPS`, or `SVCB`.
- `target` is a literal DNS name. For HTTPS and SVCB service records, `.` means
  the current host. For external CNAME or service targets, use a fully qualified
  DNS name with a trailing dot.
- `ttl` sets a record's time to live (TTL) in seconds and overrides `default_ttl`.
  The default is 300 seconds. TTLs must be positive.

### HTTPS and SVCB fields

Set `priority` and `target` for each HTTPS or SVCB record. The following service
fields are optional:

| Field | Example |
|-------|---------|
| `port` | `8443` |
| `alpn` | `["h2", "http/1.1"]` |
| `no_default_alpn` | `true` |
| `ipv4hint` | `["203.0.113.10"]` |
| `ipv6hint` | `["2001:db8::1"]` |

A port must be nonzero. Priority `0` selects alias mode, which can't include
service fields. The complete encoded DNS payload must fit PKARR's 1000-byte DNS
packet limit.

### Validate and update records

Before restarting, run
`pubky-tls-proxy --config /etc/pubky-tls-proxy/config.toml --check`, replacing
`/etc/pubky-tls-proxy/config.toml` with your configuration file's path.

An invalid file causes startup to fail with a diagnostic. While the proxy is
running, an invalid edit leaves the last valid packet in place. The proxy logs
the error until you correct the file.

Valid record changes publish promptly. Changes to comments, spacing, or record
order don't trigger a publication. Clients may continue to use old records
until their TTL expires.

If another writer uses the same secret key, the proxy tries to publish a newer
packet built from the local DNS records file. It logs repeated conflicts.

### Switch to external-packet mode

1. Set `mode = "external-packet"` in the `[pkarr]` section.
2. Remove any explicitly configured `dns_records_file`.
3. Restart the proxy.

Deleting the records file alone never changes the publishing mode. See
[external-packet mode](#external-packet-mode) for its requirements.

## PROXY protocol

Backends see connections from the proxy rather than directly from clients. To
provide the original client address, the proxy starts each backend connection
with a [PROXY protocol v1 header](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt),
such as `PROXY TCP4 203.0.113.7 10.0.0.1 51000 443`.

Headers are enabled by default. Configure each backend to accept them. In nginx,
add `proxy_protocol` to the relevant `listen` directive:
`listen ... proxy_protocol;`.

If your backend doesn't support the PROXY protocol, pass `--no-proxy-protocol`
or set `proxy_protocol = false` in the configuration file.

## Logging

The proxy writes logs to stdout at `info` level by default. For more detail, set
`RUST_LOG=pubky_tls_proxy=debug` in the environment of the proxy process.

Clients that disconnect or stay silent are logged only at `debug` level. For
initialization logging, see [Prepare the files](#prepare-the-files).

## Shutdown

On Unix, press Ctrl+C (`SIGINT`) or send `SIGTERM` to start shutdown. systemd and
container runtimes also send `SIGTERM` when stopping the service. On other
platforms, use Ctrl+C.

During shutdown, the proxy stops accepting connections and stops packet
republishing. Active connections have up to five seconds to finish. If any
remain, the proxy cancels them and exits with a shutdown timeout error.

## Running directly in front of a Pubky homeserver

The proxy can handle raw public key TLS and forward decrypted HTTP directly to
a Pubky homeserver without nginx. A homeserver doesn't support the PROXY
protocol, so disable headers for this setup.

First, prepare the required files with `init` and review the DNS records. Then
run the following command to listen on port `8443` and forward HTTP to the
homeserver at `127.0.0.1:6286`. The relative path `secret` selects the key in your
configuration directory:

```bash
pubky-tls-proxy --secret-key-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

## Creating a secret key

### Generate and select a key

`init` generates and saves a secret key if the file is missing. It creates parent
directories as needed and requires write access to the directory. Startup and
`--check` require the saved key.

The default key file is `~/.pubky-tls-proxy/secret`. To use another path:

- Before initialization, set `secret_key_file` in an existing configuration file
  to choose where `init` creates or reads the key.
- At runtime, pass `--secret-key-file` to select an existing key.

When you use `--config`, the default key file is `secret` in that configuration
file's directory. It must exist before startup.

To prepare the key and other required files, run `init`. Review the generated
configuration and DNS records before running `--check` and starting the proxy:

```bash
pubky-tls-proxy init
pubky-tls-proxy --check
pubky-tls-proxy
```

The initialization output shows the public key and secret key file's location,
never the secret key itself.

### Keep the same identity

Subsequent starts reuse the saved key. Empty, malformed, or unreadable key files
cause an error and are never replaced. New secret key files have owner-only
permissions (`0600`) on Unix.

Keep the secret key private and back it up to retain control of your Public Key
Domain. Generating a replacement key creates a different Public Key Domain.

To make a new Public Key Domain discoverable, use a
[DNS records file](#publishing-dns-records) with an A record for the server and
an HTTPS record for the proxy's public listen port. Use port `8443` for the
[separate-port nginx setup](guides/nginx-letsencrypt.md) or port `443` for the
[shared-port setup](guides/nginx-letsencrypt-shared-port.md).
