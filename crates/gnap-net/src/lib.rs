//! Small network-address policies shared by the GNAP example applications.
//!
//! This crate supplies address classification only, not an SSRF-safe HTTP
//! client. Callers must also constrain URLs, inspect and pin all resolved
//! addresses, disable redirects and enforce their own time and size limits.

use std::net::IpAddr;

/// Conservative public-unicast policy: deliberately excludes some legitimate
/// special-purpose public ranges. False negatives are safer than an SSRF path.
#[must_use]
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Native global unicast only; no mapped IPv4, NAT64, transition,
            // documentation, local, multicast or unknown future allocation.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::public_ip;

    #[test]
    fn denies_private_metadata_and_transition_addresses() {
        for address in [
            "0.0.0.0",
            "10.2.3.4",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.2",
            "203.0.113.5",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "64:ff9b::a00:1",
            "2002:7f00:1::1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(public_ip(address.parse().unwrap()), "{address}");
        }
    }
}
