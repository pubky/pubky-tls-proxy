# Terminology

Use these terms consistently in documentation, CLI help, logs, and source comments.

| Term | Meaning |
|------|---------|
| **Public Key Domain** | A domain named by an encoded public key. Its DNS records are discovered through PKARR. Changing its server address does not change the domain. |
| **Conventional DNS domain** | A domain such as `example.com`, used when contrasting conventional DNS with a Public Key Domain. |
| **Public key** | The cryptographic public key; its encoded form names the Public Key Domain. |
| **Secret key** | The private key material used for raw public key TLS and signing PKARR packets. The **secret key file** stores it. |
| **Keypair** | The public key and its corresponding secret key. |
| **Raw public key TLS** | TLS using raw public keys as specified by RFC 7250; abbreviated **RPK TLS** when needed. |
| **Certificate-based HTTPS** | HTTP over certificate-based TLS. Use **certificate-based TLS** when describing the TLS mechanism itself. |
| **Plain HTTP** | HTTP without TLS. |
| **HTTP backend** | The service receiving plain HTTP and HTTP decrypted from raw public key TLS. |
| **TLS passthrough backend** | The service receiving encrypted TLS traffic and handling its TLS handshake, normally for certificate-based HTTPS. |
| **TLS passthrough** | Forwarding TLS traffic without decrypting it. This also describes the internal fallback route for unparseable TLS handshakes. |
| **PKARR packet** | The signed object containing DNS records published through PKARR. Signing is implied by this term. |
| **DNS records file** | The TOML file defining the complete record set to publish, normally `dns-records.toml`. |
| **Local-records mode** | Publishing DNS records from a local file, then republishing the PKARR packet periodically. |
| **External-packet mode** | Resolving and republishing an externally published PKARR packet unchanged. |
| **Publish / republish** | Make a PKARR packet available / publish an existing packet again. |

Use **PKARR**, **Mainline DHT** (then **DHT**), and **PROXY protocol v1 header**
(then **PROXY protocol header**) in prose. Use **Pubky TLS Proxy** for the product
and `pubky-tls-proxy` for the executable, package, and service.

Keep literal commands, configuration keys, filenames, URLs, and dependency API
names in their required spelling, including `pkarr` and `SignedPacket`.

Use `pkarr` in configuration keys and snake_case identifiers, and `Pkarr` in Rust
type names. The publishing subsystem covers both initial publication and periodic
republishing; reserve `republish` for publishing an existing packet again.
