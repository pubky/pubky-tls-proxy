//! Helpers shared by tests.

use pkarr::Keypair;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore};
use std::sync::Arc;

/// The first bytes a regular HTTPS client (e.g. a browser) sends: a ClientHello offering X.509 certificates.
pub fn x509_client_hello(server_name: &str) -> Vec<u8> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

    client_hello(config, server_name)
}

/// The first bytes a Pubky client sends: a ClientHello offering only Raw Public Keys.
pub fn raw_public_key_client_hello() -> Vec<u8> {
    let pkarr_client = pkarr::Client::builder()
        .no_dht()
        .build()
        .expect("a relay-only pkarr client builds without network access");
    let config = ClientConfig::from(pkarr_client);

    client_hello(config, &Keypair::random().public_key().to_z32())
}

fn client_hello(config: ClientConfig, server_name: &str) -> Vec<u8> {
    let server_name = ServerName::try_from(server_name.to_string()).expect("valid server name");
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).expect("valid client config");

    let mut client_hello = Vec::new();
    while connection.wants_write() {
        connection
            .write_tls(&mut client_hello)
            .expect("writing to a Vec never fails");
    }
    client_hello
}
