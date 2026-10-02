# Share ports 80 and 443 between nginx and Pubky TLS Proxy

Use this guide to serve a website over certificate-based HTTPS and raw public
key TLS on the same public port, 443. Pubky TLS Proxy also listens on port 80
for HTTP redirects and Let's Encrypt certificate validation.

Choose this setup if clients cannot reach port 8443. Otherwise, use the
[separate-port guide](nginx-letsencrypt.md), which leaves nginx on public ports
80 and 443. A browser or another application may support either or both TLS
connection types.

```text
Certificate-based HTTPS ──> proxy :443 ──> nginx :8443 ──> website
Raw public key TLS ───────> proxy :443 ──> nginx :8080 ──> website
Plain HTTP ──────────────> proxy :80 ───> nginx :8080 ──> website
```

The proxy decrypts raw public key TLS and passes certificate-based HTTPS through
without decrypting it. nginx handles the Let's Encrypt certificate and listens
only on localhost.

The commands were tested on Debian 13 and also apply to Debian 12 and Ubuntu
24.04. This guide uses Pubky TLS Proxy v0.5.0.

## Before you begin

You need:

- A server with a public IPv4 address and a user with `sudo` access.
- TCP ports 80 and 443 open to the public in the server and cloud firewalls.
- A conventional DNS domain whose A record points to the server's public IPv4 address.

Replace `example.com` with your domain in every command, file name, and
configuration example. Have the server's public IPv4 address ready so you can
check the generated DNS records.

You will use `init` to prepare the configuration, secret key, and DNS records
before starting the proxy. The service requires the saved secret key and reuses
it on later starts.

Your conventional DNS domain is used for requests to `example.com` and for
Let's Encrypt certificate validation. The proxy also builds a packet from
`dns-records.toml`, signs it, and publishes it through
[PKARR](https://github.com/pubky/pkarr). These records let applications discover
the server by its Public Key Domain, a domain named by an encoded public key.
PKARR discovery is separate from TLS.

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install nginx certbot nano curl
```

nginx's default site uses port 80, which the proxy needs. Remove the default
site's link from `sites-enabled`, then reload nginx:

```bash
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl reload nginx
```

## 2. Create the website

### Create the page

Create the website directory and open a new page:

```bash
sudo mkdir -p /var/www/example.com
sudo nano /var/www/example.com/index.html
```

Add the following HTML, replacing `example.com` with your domain:

```html
<h1>Hello from example.com</h1>
```

Save the file in nano with Ctrl+O, then press Enter. Exit with Ctrl+X. Use these
keys to save and close the other files you edit in this guide.

### Configure the HTTP backend

nginx must serve plain HTTP before Let's Encrypt can validate your domain.
Open a new nginx site configuration:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Add the following configuration, replacing `example.com` in the `root`
directive. This site initially accepts requests for any `Host` header. In step 6,
you will add a domain-specific redirect after obtaining the certificate.

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

Save the file. Enable the site, check the nginx configuration, and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Install Pubky TLS Proxy

Download the v0.5.0 binary and its checksum file. The following commands use
`linux-amd64`. For a 64-bit ARM server, select the matching archive on the
[releases page](https://github.com/pubky/pubky-tls-proxy/releases) and replace the
platform in the commands.

```bash
mkdir -p ~/pubky-tls-proxy-download
cd ~/pubky-tls-proxy-download
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.5.0/pubky-tls-proxy-linux-amd64-v0.5.0.tar.gz
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.5.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Confirm that the checksum check prints `OK` for the downloaded archive before
continuing. Extract and install the binary, then check its version:

```bash
tar -xzf pubky-tls-proxy-linux-amd64-v0.5.0.tar.gz
sudo cp pubky-tls-proxy-linux-amd64-v0.5.0/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
sudo chmod 755 /usr/local/bin/pubky-tls-proxy
pubky-tls-proxy --version
```

## 4. Configure the proxy

### Initialize the files

This guide runs the proxy as your login user. As that user, without `sudo`,
prepare the configuration, secret key, and A and HTTPS records in
`~/.pubky-tls-proxy/`:

```bash
pubky-tls-proxy init --port 443
```

`init` creates the files without publishing records or starting listeners.
`--port 443` sets the advertised port; it doesn't change the listeners in
`config.toml`. Configure the listeners below, then review the detected IP address
and advertised port. For details, see
[initialization](../configuration.md#initialization).

### Configure the listeners and backends

Open the configuration file:

```bash
nano ~/.pubky-tls-proxy/config.toml
```

Replace the starter configuration with the following and save the file:

```toml
listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
http_backend_addr = "127.0.0.1:8080"
tls_passthrough_backend_addr = "127.0.0.1:8443"
# Leave plain HTTP enabled (the default) for redirects and Let's Encrypt challenges.

[pkarr]
dns_records_file = "dns-records.toml"
```

The proxy listens on public ports 80 and 443. nginx receives plain HTTP and
decrypted raw public key TLS traffic on port 8080. After step 6, it also receives
encrypted certificate-based HTTPS on port 8443.

By default, the proxy uses `secret` and `pkarr-packet.cache` in the same directory
as `config.toml`.

### Review DNS records for your Public Key Domain

Open the DNS records file created by `init`. The `dns_records_file` setting
requires this file to exist:

```bash
nano ~/.pubky-tls-proxy/dns-records.toml
```

Check these values:

- The A record contains the server's public IPv4 address.
- The HTTPS record uses `port = 443`, the public port, not nginx's internal port 8443.

Correct the address if detection found an outbound address that differs from the
address clients connect to.

`@` means the apex of your Public Key Domain. In the HTTPS record,
`target = "."` refers to the same host, and `port = 443` tells clients to use
the shared public port.

### Validate the configuration

Validate the files as your login user, without `sudo`:

```bash
pubky-tls-proxy --check
```

Confirm that the command prints `Configuration and DNS records are valid`.
The check requires the files prepared by `init`, runs offline, and creates no
files. The service publishes the DNS records when it starts.

## 5. Start the proxy

### Create the systemd service

Find your username and the absolute path to your home directory:

```bash
whoami
printenv HOME
```

Open the systemd service file:

```bash
sudo nano /etc/systemd/system/pubky-tls-proxy.service
```

Add the following service definition with these substitutions:

- Replace `alice` with your username.
- Replace `/home/alice` with the home directory path printed above.
- Use the full path in `ExecStart`, not `~`.

Once enabled, the service starts at boot and runs as your user, including when
you're logged out. `AmbientCapabilities` lets it bind ports 80 and 443 without
running as root.

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

### Start the service and check its log

Save the service file. Enable and start the service, then inspect its log:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pubky-tls-proxy
sudo journalctl -u pubky-tls-proxy -n 30 --no-pager
```

Check the log for:

- Your public key.
- `Listening on 0.0.0.0:80` and `Listening on 0.0.0.0:443`.
- `Managing 2 DNS records from ...`, followed by
  `Published local PKARR packet to DHT` or
  `Published local PKARR packet to relays`.

Publishing may take a little while. Check the log again if the publication message
hasn't appeared.

### Back up the secret key

The secret key created by `init` at `~/.pubky-tls-proxy/secret` has owner-only permissions.
Back it up securely to retain control of your Public Key Domain. Generating a
replacement key creates a different Public Key Domain. Keep using the same directory across updates.

## 6. Set up certificate-based HTTPS

### Obtain the certificate

Let's Encrypt validates your domain on port 80. The proxy forwards the plain
HTTP request to nginx, which serves the challenge from the website directory.
Run certbot, replacing `example.com` in both places:

```bash
sudo certbot certonly --webroot -w /var/www/example.com -d example.com --deploy-hook "systemctl reload nginx"
```

Follow the prompts to enter your email address and accept the terms. The deploy
hook reloads nginx after future certificate renewals.

### Configure HTTPS and HTTP redirects

Open the nginx site configuration again:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Replace the entire file with the following configuration. Replace every
`example.com`, including in the certificate paths.

The first server block handles certificate-based HTTPS on `127.0.0.1:8443` and
serves decrypted raw public key TLS requests on `127.0.0.1:8080`. The second
block redirects HTTP requests for your conventional DNS domain, except for
certificate validation requests. Requests addressed to your Public Key Domain
use that domain in the `Host` header, so they aren't redirected.

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

Save the file, check the nginx configuration, and reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Verify the setup

### Check HTTPS and certificate renewal

Run these checks, replacing `example.com` with your domain:

```bash
curl -I http://example.com
curl https://example.com
sudo certbot renew --dry-run
```

Confirm that:

- The HTTP request redirects to HTTPS.
- The HTTPS request prints your page without a certificate error.
- The certificate renewal test succeeds.

### Check raw public key TLS

Use OpenSSL 3.2 or newer, which is available on Debian 13. On Debian 12 or Ubuntu
24.04, run the following command from another computer with a newer OpenSSL:

```bash
openssl s_client -connect example.com:443 -enable_server_rpk
```

Look for `Server-to-client raw public key negotiated`. This confirms that the
proxy accepts raw public key TLS connections. It doesn't verify that the
presented public key is yours.

To verify the server's identity, use a browser or application that supports
Public Key Domains and raw public key TLS. Find your public key in
`sudo journalctl -u pubky-tls-proxy -n 30 --no-pager`. To inspect its PKARR packet,
open `https://pkarr.pubky.org/<your-public-key>`, replacing `<your-public-key>`
with your encoded public key.

## Serve an app instead of static files

If your app listens on `127.0.0.1:3000`, edit the first nginx server block in
step 6. Replace the `root`, `index`, and `location /` directives with the
following block:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep the `/.well-known/acme-challenge/` location in the second server block so
certificate renewals continue to work. Check the configuration with
`sudo nginx -t`, then reload nginx with `sudo systemctl reload nginx`.

## Update the DNS records for your Public Key Domain

If the server's public IP address changes, edit
`~/.pubky-tls-proxy/dns-records.toml` and save the file. Your Public Key Domain
stays the same.

The proxy checks the file every three seconds and publishes valid changes
automatically. You don't need to restart it. It also republishes the PKARR packet
every hour to keep the records available.

If an edit is invalid, the proxy logs the error and keeps the last valid records
until you fix the file. Clients may use old records until their time to live
(TTL) expires, which is 300 seconds by default.

Changes to `config.toml`, such as a new listen port, require a service restart.

## Troubleshooting

### The proxy can't bind port 80 or 443

Another service may be using the port, often nginx's default site. Run
`sudo ss -tlnp` and check that no nginx site listens on a public port.

### Raw public key TLS connections fail

Check the A record's address and `port = 443` in `dns-records.toml`. Clients may
cache an old value until its TTL expires.

### The proxy reports DNS records file errors

Check that `~/.pubky-tls-proxy/dns-records.toml` exists and passes
`pubky-tls-proxy --check` as your login user. Keep
`dns_records_file = "dns-records.toml"` in the `[pkarr]` section. If you changed
publishing settings, make sure publishing is still enabled.

### DHT publishing fails but relay publishing succeeds

If your network blocks Mainline DHT traffic (UDP), add
`dht_bootstrap_nodes = []` to the existing `[pkarr]` section in `config.toml`.
Restart the proxy. The relays publish to the DHT on your behalf.

### Requests return `502 Bad Gateway`

Check `sudo nginx -t` and `sudo systemctl status nginx`. nginx must listen on
`127.0.0.1:8080` with `proxy_protocol` enabled.

### Certificate-based HTTPS connections close unexpectedly

Check that nginx listens on `127.0.0.1:8443` with `ssl proxy_protocol` and that
the proxy's `tls_passthrough_backend_addr` setting uses that address.

### certbot can't reach the validation challenge

Confirm that the domain's A record points to this server and TCP port 80 is open.
Test `curl -I http://example.com`.

### Enable debug logging

For more detail, add `Environment=RUST_LOG=pubky_tls_proxy=debug` under
`[Service]` in the systemd service file. Then run
`sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- Review all settings in the [configuration reference](../configuration.md).
- To leave nginx on public ports 80 and 443 and run the proxy on port 8443,
  follow the [separate-port guide](nginx-letsencrypt.md).

### Update the proxy

1. Download and verify a newer version using the procedure in step 3.
2. Stop the service with `sudo systemctl stop pubky-tls-proxy` before replacing
   the running binary.
3. Install the new binary as described in step 3. Keep the existing
   `~/.pubky-tls-proxy/` directory and secret key.
4. Start the service with `sudo systemctl start pubky-tls-proxy` and check its log.
