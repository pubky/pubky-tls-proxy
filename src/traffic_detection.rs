//! Decides where an incoming connection goes by inspecting the first bytes the client sends.
//!
//! - Anything that doesn't start with a TLS handshake record is treated as plain HTTP.
//! - A TLS ClientHello that offers raw public keys ([RFC 7250]) as server certificate type
//!   is routed to the raw public key TLS acceptor, regardless of the client application.
//! - Every other TLS connection is routed to the TLS passthrough backend.
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use rustls::server::{Acceptor, CertificateType};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// First byte of a TLS record carrying a handshake message such as the ClientHello.
const TLS_HANDSHAKE_RECORD_TYPE: u8 = 0x16;

/// Upper bound for buffering a ClientHello. Real ClientHellos are a few KiB at most, even
/// with post-quantum key shares. Anything bigger is handed to the TLS passthrough backend unparsed.
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

const READ_CHUNK_BYTES: usize = 4096;

/// The kind of traffic a client started sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingTraffic {
    PlainHttp,
    RawPublicKeyTls,
    TlsPassthrough,
}

/// Result of traffic detection.
///
/// `initial_bytes` holds everything read from the client during detection. It must be
/// replayed in front of the remaining stream (see `PrefixedStream`), otherwise the
/// connection is corrupted.
pub struct DetectedTraffic {
    pub traffic: IncomingTraffic,
    pub initial_bytes: Vec<u8>,
}

/// Reads from `client` until the kind of traffic is known.
///
/// Plain HTTP is recognised after the first read. For TLS, this reads until the complete
/// ClientHello has been received. A ClientHello that rustls can't parse is classified as
/// TLS passthrough so that the TLS passthrough backend can decide how to handle it.
///
/// This waits for the client indefinitely; callers should apply a timeout.
///
/// # Errors
///
/// Returns an error if reading fails or the client closes the connection before the
/// traffic kind is known.
pub async fn detect_traffic(client: &mut (impl AsyncRead + Unpin)) -> io::Result<DetectedTraffic> {
    let mut initial_bytes = Vec::new();
    read_more(client, &mut initial_bytes).await?;

    if initial_bytes[0] != TLS_HANDSHAKE_RECORD_TYPE {
        return Ok(DetectedTraffic {
            traffic: IncomingTraffic::PlainHttp,
            initial_bytes,
        });
    }

    let mut client_hello_parser = Acceptor::default();
    let mut parsed_byte_count = 0;
    let traffic = loop {
        let is_parser_buffer_full = feed_parser(
            &mut client_hello_parser,
            &initial_bytes[parsed_byte_count..],
        )
        .is_err();
        if is_parser_buffer_full {
            break IncomingTraffic::TlsPassthrough;
        }
        parsed_byte_count = initial_bytes.len();

        match client_hello_parser.accept() {
            Ok(Some(accepted)) => {
                break classify_client_hello(accepted.client_hello().server_cert_types())
            }
            Ok(None) => {} // The ClientHello is incomplete; read more below.
            Err(_unparsable_client_hello) => break IncomingTraffic::TlsPassthrough,
        }

        if initial_bytes.len() >= MAX_CLIENT_HELLO_BYTES {
            break IncomingTraffic::TlsPassthrough;
        }
        read_more(client, &mut initial_bytes).await?;
    };

    Ok(DetectedTraffic {
        traffic,
        initial_bytes,
    })
}

fn classify_client_hello(offered_server_cert_types: Option<&[CertificateType]>) -> IncomingTraffic {
    let offers_raw_public_key = offered_server_cert_types
        .is_some_and(|cert_types| cert_types.contains(&CertificateType::RawPublicKey));

    if offers_raw_public_key {
        IncomingTraffic::RawPublicKeyTls
    } else {
        IncomingTraffic::TlsPassthrough
    }
}

/// Hands all of `bytes` to the ClientHello parser. Fails if its internal buffer is full.
fn feed_parser(parser: &mut Acceptor, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        parser.read_tls(&mut bytes)?;
    }
    Ok(())
}

/// Appends the next chunk of client data to `buffer`.
async fn read_more(client: &mut (impl AsyncRead + Unpin), buffer: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let byte_count = client.read(&mut chunk).await?;
    if byte_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "client closed the connection before its traffic could be classified",
        ));
    }
    buffer.extend_from_slice(&chunk[..byte_count]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{raw_public_key_client_hello, x509_client_hello};

    async fn detect(client_bytes: &[u8]) -> io::Result<DetectedTraffic> {
        let mut client = client_bytes;
        detect_traffic(&mut client).await
    }

    #[tokio::test]
    async fn http_request_is_plain_http() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let detected = detect(request).await.unwrap();

        assert_eq!(detected.traffic, IncomingTraffic::PlainHttp);
        assert_eq!(detected.initial_bytes, request);
    }

    #[tokio::test]
    async fn client_hello_offering_raw_public_key_is_raw_public_key_tls() {
        let client_hello = raw_public_key_client_hello();

        let detected = detect(&client_hello).await.unwrap();

        assert_eq!(detected.traffic, IncomingTraffic::RawPublicKeyTls);
        assert_eq!(detected.initial_bytes, client_hello);
    }

    #[tokio::test]
    async fn client_hello_offering_only_x509_is_tls_passthrough() {
        let client_hello = x509_client_hello("example.com");

        let detected = detect(&client_hello).await.unwrap();

        assert_eq!(detected.traffic, IncomingTraffic::TlsPassthrough);
        assert_eq!(detected.initial_bytes, client_hello);
    }

    #[tokio::test]
    async fn client_hello_split_across_reads_is_detected() {
        let client_hello = raw_public_key_client_hello();
        let (first_half, second_half) = client_hello.split_at(client_hello.len() / 2);
        let mut client = reader_returning_chunks(&[first_half, second_half]);

        let detected = detect_traffic(&mut client).await.unwrap();

        assert_eq!(detected.traffic, IncomingTraffic::RawPublicKeyTls);
        assert_eq!(detected.initial_bytes, client_hello);
    }

    #[tokio::test]
    async fn tls_handshake_that_is_not_a_client_hello_is_tls_passthrough() {
        // record header: handshake, TLS 1.0, 4 bytes | message: ServerHello (type 2), 0 bytes
        let server_hello_record: &[u8] = &[TLS_HANDSHAKE_RECORD_TYPE, 3, 1, 0, 4, 2, 0, 0, 0];

        let detected = detect(server_hello_record).await.unwrap();

        assert_eq!(detected.traffic, IncomingTraffic::TlsPassthrough);
    }

    #[tokio::test]
    async fn client_closing_before_sending_anything_is_an_error() {
        let result = detect(b"").await;

        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::UnexpectedEof)
        );
    }

    /// A reader that returns each chunk in a separate `read` call.
    fn reader_returning_chunks(chunks: &[&[u8]]) -> impl AsyncRead + Unpin {
        let mut builder = tokio_test::io::Builder::new();
        for chunk in chunks {
            builder.read(chunk);
        }
        builder.build()
    }
}
