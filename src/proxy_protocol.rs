//! PROXY protocol version 1 header, as specified by HAProxy:
//! <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>
//!
//! A backend such as nginx (`listen ... proxy_protocol;`) reads this header to learn the
//! real client address, because every connection it receives comes from this proxy.

use std::net::SocketAddr;

/// Builds the PROXY protocol v1 header announcing a connection from `client_addr` to `proxy_addr`.
///
/// IPv4-mapped IPv6 addresses (e.g. `::ffff:1.2.3.4`, seen when listening on `[::]`) are
/// reported as plain IPv4. If client and proxy address families still differ, the header
/// is `PROXY UNKNOWN`, which tells the backend to use the real connection addresses.
pub fn v1_header(client_addr: SocketAddr, proxy_addr: SocketAddr) -> String {
    let client_ip = client_addr.ip().to_canonical();
    let proxy_ip = proxy_addr.ip().to_canonical();

    let protocol = match (client_ip.is_ipv4(), proxy_ip.is_ipv4()) {
        (true, true) => "TCP4",
        (false, false) => "TCP6",
        _ => return "PROXY UNKNOWN\r\n".to_string(),
    };

    format!(
        "PROXY {protocol} {client_ip} {proxy_ip} {} {}\r\n",
        client_addr.port(),
        proxy_addr.port()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn ipv4_connection() {
        let header = v1_header(addr("203.0.113.7:51000"), addr("10.0.0.1:443"));

        assert_eq!(header, "PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n");
    }

    #[test]
    fn ipv6_connection() {
        let header = v1_header(addr("[2001:db8::7]:51000"), addr("[2001:db8::1]:443"));

        assert_eq!(header, "PROXY TCP6 2001:db8::7 2001:db8::1 51000 443\r\n");
    }

    #[test]
    fn ipv4_mapped_ipv6_is_reported_as_ipv4() {
        let header = v1_header(
            addr("[::ffff:203.0.113.7]:51000"),
            addr("[::ffff:10.0.0.1]:443"),
        );

        assert_eq!(header, "PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n");
    }

    #[test]
    fn mixed_address_families_are_unknown() {
        let header = v1_header(addr("203.0.113.7:51000"), addr("[2001:db8::1]:443"));

        assert_eq!(header, "PROXY UNKNOWN\r\n");
    }
}
