# Configuration migration

## Upcoming release: explicit setup and publishing modes

Startup and `--check` now require an existing configuration and secret key. They
never create setup files. Run `pubky-tls-proxy init` before starting a fresh
installation, or prepare the files through your deployment tooling. For a custom
directory use `init --directory /path/to/proxy`, then
`--config /path/to/proxy/config.toml` when checking or running.

Keep existing secret keys to retain your Public Key Domain. If the files already
exist, `init` validates and preserves them. Back up the key generated during setup.

Local-record publishing is the default and requires `dns-records.toml` beside the
config, or the explicitly configured records file. Existing local-record deployments
need no mode setting. Removing the records file now fails startup rather than
silently switching to external-packet republishing.

For externally managed records, explicitly select:

```toml
[pkarr]
mode = "external-packet"
```

Alternatively, pass `--pkarr-mode external-packet`. Remove any explicitly configured
`dns_records_file`; it conflicts with external-packet mode. The default records file,
if present, is ignored in that mode. Set this mode **before running init** for an
existing externally managed identity so setup does not create local records.

`[pkarr] publish = false` or `--no-pkarr-publish` removes the records requirement
for both startup and `--check`, but config and key remain required. `--check` now
validates only files required by the selected deployment. Packet cache files remain
optional and are created by the publisher as needed.

These breaking changes belong in the next minor release while the project is pre-1.0.

## Migrating to 0.4.0

Version **0.4.0 introduces breaking changes** to CLI options and configuration keys.
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
