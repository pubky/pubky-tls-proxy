# Share ports 80 and 443 between nginx and Pubky TLS Proxy

This is the alternative to the [simpler nginx and Let's Encrypt guide](nginx-letsencrypt.md), where raw public key TLS uses port 8443. Here, **certificate-based TLS and raw public key TLS share port 443**. Choose this if clients cannot reach port 8443. A browser or another application may support either or both connection types.

```text
Certificate-based HTTPS ──> proxy :443 ──> nginx :8443 ──> website
Raw public key TLS ───────> proxy :443 ──> nginx :8080 ──> website
Plain HTTP ──────────────> proxy :80 ───> nginx :8080 ──> website
```

The proxy decrypts raw public key TLS but passes certificate-based HTTPS through untouched, so nginx handles the Let's Encrypt certificate. nginx only listens on localhost. This setup was tested on Debian 13; the same commands apply to Debian 12 and Ubuntu 24.04.

## Before you begin

You need a server with `sudo` access, TCP ports **80 and 443** open to the public, and a conventional DNS domain whose A record points to your server. This guide calls that domain `example.com`: **replace it with yours in every file name, command, and configuration example**.

Have the server's public IPv4 address ready. The proxy generates your secret key on first startup and reuses it on later starts.

Your conventional DNS domain's record is for requests to `example.com` and Let's Encrypt. The proxy builds a PKARR packet from `dns-records.toml`, signs and publishes it through PKARR, letting applications discover the server by its Public Key Domain. This discovery is separate from TLS.

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install nginx certbot nano curl
```

nginx's default site uses port 80, which the proxy needs. Remove its **enabled link** and reload nginx:

```bash
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl reload nginx
```

## 2. Create the website

Make a directory and a test page:

```bash
sudo mkdir -p /var/www/example.com
sudo nano /var/www/example.com/index.html
```

Paste this page, replacing `example.com` with your domain. Save in nano with **Ctrl+O**, Enter; exit with **Ctrl+X**:

```html
<h1>Hello from example.com</h1>
```

nginx must first serve **plain HTTP** so Let's Encrypt can check your domain. Open a new nginx site:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Paste this, replacing `example.com` in the `root` line. This site initially accepts requests for any Host header; step 6 adds the domain-specific redirect after the certificate exists.

```nginx
server {
    listen 127.0.0.1:8080 default_server proxy_protocol;
    server_name _;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
```

Save and exit. Enable the site, then test and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Install Pubky TLS Proxy

This guide uses the **unreleased configuration schema**. Build from the same source
revision as this guide using a stable Rust toolchain. The published v0.3.4 binary
does not accept the new names; its matching guide is available
[here](https://github.com/pubky/pubky-tls-proxy/blob/v0.3.4/docs/guides/nginx-letsencrypt-shared-port.md).

From your repository checkout on the server:

```bash
cargo build --release
sudo cp target/release/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
sudo chmod 755 /usr/local/bin/pubky-tls-proxy
pubky-tls-proxy --version
```

For an existing installation, first update its configuration using the
[migration guide](../configuration-migration.md).

## 4. Configure the proxy

Run the proxy as your normal login user. Keep its configuration, secret key file, and packet cache together in `~/.pubky-tls-proxy/`. Create the directory without `sudo`:

```bash
mkdir -p ~/.pubky-tls-proxy
```

Open the config file:

```bash
nano ~/.pubky-tls-proxy/config.toml
```

Paste this and save it. The proxy owns ports 80 and 443. nginx receives decrypted raw public key TLS traffic on port 8080 and still-encrypted certificate-based HTTPS on port 8443 (after step 6). The proxy uses `secret` and `pkarr-packet.cache` beside this file by default.

```toml
listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
http_backend_addr = "127.0.0.1:8080"
tls_passthrough_backend_addr = "127.0.0.1:8443"
# Leave plain HTTP enabled (the default) for redirects and Let's Encrypt challenges.

[pkarr]
dns_records_file = "dns-records.toml"
```

### Publish DNS records for your Public Key Domain

Create the DNS records file next to the config. The `dns_records_file` setting makes this file required:

```bash
nano ~/.pubky-tls-proxy/dns-records.toml
```

Replace `203.0.113.10` with your server's public IPv4 address and save:

```toml
[[records]]
name = "@"
type = "A"
address = "203.0.113.10"

[[records]]
name = "@"
type = "HTTPS"
priority = 1
target = "."
port = 443
```

`@` means the apex of your Public Key Domain. In the HTTPS record, `target = "."` uses that same host, and `port = 443` tells clients to use the shared public port. Use 443 here, not nginx's internal port 8443.

Validate the files as your normal user, without `sudo`:

```bash
pubky-tls-proxy --check
```

Look for `Configuration and DNS records are valid`. On first setup, the check also reports that the secret key file is missing and will be generated at startup. On later checks, it validates the saved secret key too. The check runs offline and creates no secret key file; on first startup, the service generates a keypair, saves the secret key, and publishes the DNS records.

## 5. Start the proxy

Find your username and absolute home directory path:

```bash
whoami
printenv HOME
```

Open the systemd service file:

```bash
sudo nano /etc/systemd/system/pubky-tls-proxy.service
```

Paste the following, replacing `alice` with your username and `/home/alice` with the home path printed above. Use the full path in `ExecStart`, not `~`. The service starts at boot and runs as your user, even when you are logged out. `AmbientCapabilities` lets it bind ports **80 and 443** without running as root:

```ini
[Unit]
Description=Pubky TLS Proxy
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=alice
ExecStart=/usr/local/bin/pubky-tls-proxy --config /home/alice/.pubky-tls-proxy/config.toml
Restart=on-failure
RestartSec=5s

AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Start it and inspect the log:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pubky-tls-proxy
sudo journalctl -u pubky-tls-proxy -n 30 --no-pager
```

Look for your public key, `Listening on 0.0.0.0:80`, and `Listening on 0.0.0.0:443`. For DNS publishing, look for `Managing 2 DNS records from ...`, followed by `Published local PKARR packet to DHT` or `Published local PKARR packet to relays`. Publishing may take a little while; check the log again if needed.

The proxy creates `~/.pubky-tls-proxy/secret` with owner-only permissions on first startup. Back it up securely after the first successful start to retain control of your Public Key Domain. Generating a replacement key creates a different Public Key Domain. Keep using the same directory across updates.

## 6. Set up certificate-based HTTPS

Let's Encrypt checks your domain on port 80. The proxy forwards that plain HTTP request to nginx, which serves the challenge from the website directory:

```bash
sudo certbot certonly --webroot -w /var/www/example.com -d example.com --deploy-hook "systemctl reload nginx"
```

Replace `example.com` in both places. certbot asks for an email address and to accept its terms. The deploy hook reloads nginx after future renewals.

Now edit the nginx site again:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

**Replace its entire contents** with the following. Replace **every** `example.com`, including in the certificate paths. nginx now terminates certificate-based HTTPS on localhost:8443; the second block redirects HTTP requests for your conventional DNS domain. Requests addressed to your Public Key Domain use that domain in the `Host` header, so they aren't redirected.

```nginx
server {
    listen 127.0.0.1:8080 default_server proxy_protocol;
    listen 127.0.0.1:8443 default_server ssl proxy_protocol;
    server_name _;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}

server {
    listen 127.0.0.1:8080 proxy_protocol;
    server_name example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/example.com;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
```

Save, check and reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Verify the setup

Replace `example.com` with your domain:

```bash
curl -I http://example.com
curl https://example.com
sudo certbot renew --dry-run
```

HTTP should redirect to HTTPS, the HTTPS request should show your page with a valid certificate, and the renewal test should succeed.

To check raw public key TLS, use OpenSSL **3.2 or newer** (Debian 13 has it; Debian 12 and Ubuntu 24.04 need another computer with newer OpenSSL):

```bash
openssl s_client -connect example.com:443 -enable_server_rpk
```

Look for `Server-to-client raw public key negotiated`. This doesn't verify that the key is yours; check it with a browser or application supporting Public Key Domains and raw public key TLS. The proxy's public key appears in `sudo journalctl -u pubky-tls-proxy -n 30 --no-pager`, and you can inspect its PKARR packet at `https://pkarr.pubky.org/<your-public-key>`.

## Serve an app instead of static files

If your app listens on `127.0.0.1:3000`, edit the **first** nginx server block in step 6. Replace the `root`, `index` and `location /` lines with:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep the `/.well-known/acme-challenge/` block in the second server block, so certificate renewals work.

## Update the DNS records for your Public Key Domain

If the server's public IP address changes, edit `~/.pubky-tls-proxy/dns-records.toml` and save it. Your Public Key Domain stays the same. The proxy checks the file every three seconds and publishes valid changes automatically; no restart is needed. It also republishes the PKARR packet every hour to keep the records available.

If an edit is invalid, the proxy logs the error and keeps the last valid records until you fix the file. Clients may keep using old records until their TTL expires (300 seconds by default). Changes to `config.toml`, such as a new listen port, require a service restart.

## Troubleshooting

- **The proxy can't bind port 80 or 443:** Something else uses it, often nginx's default site. Run `sudo ss -tlnp` and check that no nginx site listens on a public port.
- **Raw public key TLS connections fail:** Check the A address and `port = 443` in `dns-records.toml`; clients may cache an old value until its TTL expires.
- **DNS records file errors:** Check that `~/.pubky-tls-proxy/dns-records.toml` exists and passes `pubky-tls-proxy --check` as your normal user. Keep `dns_records_file = "dns-records.toml"` under `[pkarr]`. If you have changed publishing settings, make sure publishing is still enabled.
- **DHT errors, but publishing to relays succeeds:** If your network blocks DHT (UDP), add `dht_bootstrap_nodes = []` to the existing `[pkarr]` section in `config.toml`. Restart the proxy. The relays publish to the DHT for you.
- **`502 Bad Gateway`:** nginx must listen on `127.0.0.1:8080`. Check `sudo nginx -t` and `sudo systemctl status nginx`.
- **Certificate-based HTTPS disconnects:** Check that nginx listens on `127.0.0.1:8443` with `ssl proxy_protocol` and that the proxy config names it as `tls_passthrough_backend_addr`.
- **certbot can't reach the challenge:** Check the domain's A record, open TCP port 80, and test `curl -I http://example.com`.

For more detail, add `Environment=RUST_LOG=pubky_tls_proxy=debug` under `[Service]` in the systemd unit. Then run `sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- [Configuration](../configuration.md) covers all settings.
- To update the proxy, install a newer version as in step 3. Stop the service with `sudo systemctl stop pubky-tls-proxy` before copying over the running binary; then start it with `sudo systemctl start pubky-tls-proxy`.
- To leave nginx on public ports 80/443 and run the proxy on 8443 instead, use the [simpler guide](nginx-letsencrypt.md).
