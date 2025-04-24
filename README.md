# PKarr TLS Certificate Proxy

This tool acts as a TLS terminating proxy for PKarr Raw Public Key (RPK) certificates. It allows you to:

1. Load a PKarr secret key from a file
2. Create a TLS server using PKarr's self-signed certificate implementation (RFC 7250)
3. Forward decrypted traffic to another service

## Installation

```bash
cargo install --path .
```

## Usage

```bash
pkarr-rusttls-certs-converter --secret-file <PATH_TO_SECRET_KEY> --backend-addr <BACKEND_ADDRESS> --listen-addr <LISTEN_ADDRESS>
```

### Arguments

- `--secret-file`: Path to a file containing the pkarr secret key in HEX format (must be 32 bytes/64 hex characters)
- `--backend-addr`: Address to proxy requests to after TLS termination (e.g., 127.0.0.1:8080)
- `--listen-addr`: Address to listen on for incoming TLS connections (e.g., 0.0.0.0:8443)

### Example

To create a proxy that:
- Listens for TLS connections on port 8443
- Uses a pkarr secret key from `secret.hex`
- Forwards decrypted traffic to a local service on port 3000

```bash
pkarr-rusttls-certs-converter --secret-file secret.hex --backend-addr 127.0.0.1:3000 --listen-addr 0.0.0.0:8443
```

### Creating a Secret Key File

To generate a new secret key:

```bash
# Generate a 32-byte random secret and save as hex
openssl rand -hex 32 > secret.hex
```

## How It Works

This proxy:

1. Loads the secret key and creates a PKarr keypair
2. Uses PKarr's `to_rpk_rustls_server_config()` to generate a TLS configuration
3. Sets up a TLS listener using the config
4. For each connection:
   - Terminates the TLS
   - Opens a TCP connection to the backend
   - Bidirectionally copies data between the client and backend

## License

MIT 