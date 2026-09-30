# Configuration migration

These **unreleased breaking changes** rename CLI options and configuration keys.
They do not change routing, key formats, default file locations, or publishing behavior.
The old names are rejected rather than retained as aliases.

## CLI options

Update command invocations, scripts, container arguments, and systemd `ExecStart`
lines using this table:

| Old option | New option |
|------------|------------|
| `--secret-file` | `--secret-key-file` |
| `--https-backend-addr` | `--tls-passthrough-backend-addr` |
| `--handshake-timeout-secs` | `--rpk-handshake-timeout-secs` |
| `--backend-timeout-secs` | `--backend-setup-timeout-secs` |
| `--no-republish` | `--no-pkarr-publish` |
| `--republish-interval-secs` | `--pkarr-republish-interval-secs` |
| `--packet-cache-file` | `--pkarr-packet-cache-file` |
| `--pkarr-bootstrap-node` | `--pkarr-dht-bootstrap-node` |
| `--pkarr-relay` | `--pkarr-relay-url` |
| `--backend-addr` (legacy alias) | `--http-backend-addr` |

`--dns-records-file`, `--no-pkarr-dht`, and `--no-pkarr-relays` retain their names.
Repeatable options remain repeatable. RPK means **raw public key**.

## TOML keys

All publishing settings now belong to `[pkarr]`. Remove the `[republish]` table
after moving its settings. Unknown keys and tables cause a configuration error,
including when publishing is disabled.

| Old key | New key |
|---------|---------|
| `secret_file` | `secret_key_file` |
| `https_backend_addr` | `tls_passthrough_backend_addr` |
| `handshake_timeout_secs` | `rpk_handshake_timeout_secs` |
| `backend_timeout_secs` | `backend_setup_timeout_secs` |
| `[republish] enabled` | `[pkarr] publish` |
| `[republish] interval_secs` | `[pkarr] republish_interval_secs` |
| `[republish] cache_file` | `[pkarr] packet_cache_file` |
| `[pkarr] records_file` | `[pkarr] dns_records_file` |
| `[pkarr] bootstrap_nodes` | `[pkarr] dht_bootstrap_nodes` |
| `[pkarr] relays` | `[pkarr] relay_urls` |

For example, this configuration:

```toml
secret_file = "secret"
https_backend_addr = "127.0.0.1:6443"
handshake_timeout_secs = 10
backend_timeout_secs = 10

[republish]
enabled = true
interval_secs = 3600
cache_file = "pkarr-packet.cache"

[pkarr]
records_file = "dns-records.toml"
bootstrap_nodes = []
relays = ["https://pkarr.pubky.app"]
```

becomes:

```toml
secret_key_file = "secret"
tls_passthrough_backend_addr = "127.0.0.1:6443"
rpk_handshake_timeout_secs = 10
backend_setup_timeout_secs = 10

[pkarr]
publish = true
dns_records_file = "dns-records.toml"
republish_interval_secs = 3600
packet_cache_file = "pkarr-packet.cache"
dht_bootstrap_nodes = []
relay_urls = ["https://pkarr.pubky.app"]
```

The secret key file is still named `secret` by default. Keep the existing file and
its configured path to retain the same Public Key Domain. The DNS records file
and packet cache formats are unchanged.

The proxy preserves existing config files, so update their keys and commented
examples manually. Relative paths still resolve against the config directory.
CLI options override the config; disabling flags only switch features off.
`[pkarr] publish = false` and `--no-pkarr-publish` disable both initial publication
and periodic republishing. `--check` still validates DNS records when publishing
is disabled.

After editing, validate using the new binary before restarting the service:

```bash
pubky-tls-proxy --config /path/to/config.toml --check
```

If you changed a systemd unit, run `sudo systemctl daemon-reload` before restarting.
See the [configuration reference](configuration.md) for all current settings.
