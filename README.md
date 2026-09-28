# Pubky TLS Proxy

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pubky-tls-proxy)](https://github.com/pubky/pubky-tls-proxy/releases/latest/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)


This tool terminates [raw public key TLS (RFC 7250)](https://datatracker.ietf.org/doc/html/rfc7250), which Pubky uses, in front of a regular web server such as nginx. A single port can serve Pubky clients, plain HTTP and regular HTTPS side by side.

| Incoming traffic | What the proxy does                                  | Forwarded to           |
|------------------|------------------------------------------------------|------------------------|
| Plain HTTP       | forwards it unchanged                                | `--http-backend-addr`  |
| Pubky TLS        | terminates TLS with your pubky secret key            | `--http-backend-addr`  |
| Regular HTTPS    | forwards it still encrypted, the backend handles TLS | `--https-backend-addr` |

## Usage

```bash
pubky-tls-proxy [--config <FILE>] [--secret-file <FILE>] [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--https-backend-addr <ADDR>] [--no-proxy-protocol] ...
```

Every setting can be given on the command line or in a [config file](#config-file). Command line arguments override the config file. Run `pubky-tls-proxy --help` for all arguments.

### Arguments

- `--config`: Config file to use instead of `~/.pubky-tls-proxy/config.toml`. Must exist.
- `--secret-file`: File containing the pubky secret in HEX format (32 bytes/64 hex characters). Required, here or in the config file.
- `--listen-addr`: Address to listen on. Can be repeated, e.g. for ports 80 and 443 [default: 0.0.0.0:8443].
- `--http-backend-addr`: Backend for plain HTTP and decrypted Pubky TLS traffic [default: 127.0.0.1:6286]. `--backend-addr` still works as an alias.
- `--https-backend-addr`: Backend for regular HTTPS traffic. If it isn't set, regular HTTPS connections are closed.
- `--no-proxy-protocol`: Don't send a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header to the backends. See below.
- `--no-republish`: Don't [republish](#republishing-the-pkarr-packet) the pkarr packet.
- `--republish-interval-secs`: Seconds between two republish runs [default: 3600].
- `--pkarr-bootstrap-node`: Mainline DHT bootstrap node (`host:port`). Can be repeated. Replaces the default bootstrap nodes.
- `--pkarr-relay`: Pkarr relay URL. Can be repeated. Replaces the default relays.
- `--no-pkarr-dht` / `--no-pkarr-relays`: Don't republish to the DHT / to relays.

Relative paths are resolved against the directory of the config file, both in the file and on the command line. By default that's `~/.pubky-tls-proxy/`, even if no config file exists there. So `--secret-file secret` means `~/.pubky-tls-proxy/secret`.

### Config file

`~/.pubky-tls-proxy/config.toml` is read automatically if it exists. Use `--config <FILE>` to read another file instead. All keys are optional. Unknown keys are an error. This example shows the defaults:

```toml
# Required, here or with --secret-file. Relative to this file's directory.
secret_file = "secret"
listen_addrs = ["0.0.0.0:8443"]
http_backend_addr = "127.0.0.1:6286"
# https_backend_addr = "127.0.0.1:6443"   # not set: regular HTTPS is rejected
proxy_protocol = true

[republish]
enabled = true
interval_secs = 3600

[pkarr]
# A list replaces the defaults. An empty list disables that network.
bootstrap_nodes = ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881"]
relays = ["https://relay.pkarr.org", "https://pkarr.pubky.org"]
```

The command line can only switch things off (`--no-...`). If the config file says `proxy_protocol = false`, no flag turns it back on.

### Republishing the pkarr packet

DHT nodes and relays forget pkarr packets after a while unless they are published again. The proxy therefore republishes the packet of its public key: right after startup, then every `interval_secs`.

Each run resolves the most recent packet from the DHT and the relays and publishes it again **unchanged**: same records, signature and timestamp. The proxy never creates or re-signs a packet, so you still need to publish the packet once with another tool. If no packet is found, a warning is logged.

Each network is published to separately. A failed publish is retried after 1 and 5 minutes, then logged as an error. The next run starts at the next interval.

DHT bootstrap nodes are resolved once at startup. Nodes without an IPv4 address are skipped with a warning.

### PROXY protocol

The backend sees every connection coming from the proxy. So that it still knows the real client address, the proxy starts each backend connection with a PROXY protocol v1 header, e.g. `PROXY TCP4 203.0.113.7 10.0.0.1 51000 443`.

This is **on by default**. The backend must be configured to expect the header (in nginx: `listen ... proxy_protocol;`). If the backend doesn't support it, pass `--no-proxy-protocol`.

### Example: in front of nginx

The proxy owns the public ports 80 and 443, while nginx listens on localhost only. `~/.pubky-tls-proxy/config.toml`:

```toml
secret_file = "secret"
listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
http_backend_addr = "127.0.0.1:6286"
https_backend_addr = "127.0.0.1:6443"
```

Or the same on the command line:

```bash
pubky-tls-proxy --secret-file secret \
  --listen-addr 0.0.0.0:80 --listen-addr 0.0.0.0:443 \
  --http-backend-addr 127.0.0.1:6286 \
  --https-backend-addr 127.0.0.1:6443
```

```nginx
server {
    # Plain HTTP and decrypted Pubky TLS.
    listen 127.0.0.1:6286 proxy_protocol;
    # Regular HTTPS, nginx terminates TLS with its usual certificates.
    listen 127.0.0.1:6443 ssl proxy_protocol;

    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Use the client address from the PROXY protocol header.
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location / {
        proxy_pass http://127.0.0.1:8080;  # e.g. the Pubky homeserver
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_protocol_addr;
    }
}
```

Requests from Pubky clients arrive on the plain HTTP listener, so they are recognisable by their `Host` header, which is the public key, e.g. `server_name <your-z32-public-key>;`.

### Example: directly in front of a Pubky homeserver

```bash
pubky-tls-proxy --secret-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

### Creating a Secret Key File

To generate a new secret key:

```bash
# Generate a 32-byte random secret and save as hex
openssl rand -hex 32 > secret
```

## How It Works

1. The proxy loads the secret key and creates a Pubky keypair.
2. It listens on every listen address and starts republishing the pkarr packet in the background.
3. For each connection it reads the first bytes the client sends:
   - Anything that doesn't start with a TLS handshake is **plain HTTP**.
   - A TLS ClientHello that offers Raw Public Keys as server certificate type (RFC 7250) is **Pubky TLS**. Pubky clients only offer raw public keys. Browsers never do. The SNI is ignored.
   - Any other TLS ClientHello is **regular HTTPS**.
4. It opens a TCP connection to the matching backend and sends the PROXY protocol header, unless it's disabled.
5. It replays the bytes it has already read, then copies data in both directions. Pubky TLS is decrypted on the way.

If the backend is unreachable, plain HTTP and Pubky TLS clients receive a `502 Bad Gateway`. Regular HTTPS connections are closed, because only the backend can complete their TLS handshake.
