//! Reading URIs — RFC 3986.
//!
//! Several GNAP fields are required to be absolute URIs: the callback the AS
//! calls back on (§2.5.2), the continuation URI (§3.1), the token management
//! URI (§3.2.1). Each of those is a MUST about the *structure* of the value,
//! not about the characters in it: `https://[not-ipv6]/cb` and `https://h:abc/`
//! are built entirely from characters a URI may hold and are not URIs.
//!
//! So the grammar is what this module applies. It stops at syntax: whether the
//! host resolves, whether the scheme is one anybody serves, and whether the AS
//! should be making outbound calls to it at all (§11.34) are all somebody
//! else's questions.

/// Whether a string is an `absolute-URI` as RFC 3986 §4.3 defines one.
///
/// The grammar, not an alphabet: `https://[not-ipv6]/cb` and `https://h:abc/cb`
/// are built entirely from characters a URI may contain and are not URIs. The
/// §2.5.2 MUST is about the structure, so the structure is what is checked.
///
/// `absolute-URI = scheme ":" hier-part [ "?" query ]`. A fragment is therefore
/// not part of one; where the RFC forbids it separately, as §2.5.2 does, the
/// caller says so with its own message.
///
/// ```
/// use gnap_types::uri::is_absolute;
///
/// assert!(is_absolute("https://as.example/continue"));
/// assert!(is_absolute("com.example.app:/callback"));
///
/// assert!(!is_absolute("/continue"));            // relative
/// assert!(!is_absolute("https://[::1]evil/cb")); // an IP-literal ends at `]`
/// assert!(!is_absolute("https://h:abc/cb"));     // a port is digits
/// ```
#[must_use]
pub fn is_absolute(uri: &str) -> bool {
    // §3.1 — scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return false;
    }

    let (hier_part, query) = rest
        .split_once('?')
        .map_or((rest, None), |(h, q)| (h, Some(q)));
    if query.is_some_and(|q| !is_query(q)) {
        return false;
    }

    // §3 — hier-part is an authority and a path, or a path alone.
    hier_part.strip_prefix("//").map_or_else(
        // §3.3 — path-absolute, path-rootless or path-empty. An empty path is
        // one of the three: `app:` is an absolute URI, and what its handler
        // does with it is not this library's business.
        || hier_part.split('/').all(is_segment),
        |after| {
            let (authority, path) = after.split_once('/').map_or((after, ""), |(a, p)| (a, p));
            is_authority(authority) && path.split('/').all(is_segment)
        },
    )
}

/// §3.2 — `authority = [ userinfo "@" ] host [ ":" port ]`.
fn is_authority(authority: &str) -> bool {
    // The last `@` separates the userinfo, since `@` is legal inside it.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(userinfo, host)| {
            if userinfo
                .split(':')
                .all(|part| is_run(part, |b| is_unreserved(b) || is_sub_delim(b)))
            {
                host
            } else {
                // Signal the bad userinfo through a host that cannot parse.
                "["
            }
        });

    let Some((host, port)) = split_host_port(host_port) else {
        return false;
    };
    // §3.2.3 — port = *DIGIT.
    if !port.is_none_or(|p| p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    is_host(host)
}

/// Splits `host[":" port]`, leaving an IP-literal's own colons alone (§3.2.2).
///
/// `None` when the authority is not that shape at all.
fn split_host_port(host_port: &str) -> Option<(&str, Option<&str>)> {
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let (host, rest) = host_port.split_at(end + 1);
        // The grammar allows exactly one thing after the `]`: a port. Reading
        // anything else as "no port" would let `[::1]evil` through with the
        // `evil` quietly dropped, which is how a parser turns an invalid string
        // into a valid one.
        return match rest {
            "" => Some((host, None)),
            _ => Some((host, Some(rest.strip_prefix(':')?))),
        };
    }
    Some(
        host_port
            .rsplit_once(':')
            .map_or((host_port, None), |(h, p)| (h, Some(p))),
    )
}

/// §3.2.2 — `host = IP-literal / IPv4address / reg-name`.
fn is_host(host: &str) -> bool {
    let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) else {
        // A reg-name covers IPv4address as well: both are made of unreserved
        // characters, and an address that is not one is simply a name.
        return is_run(host, |b| is_unreserved(b) || is_sub_delim(b));
    };

    // §3.2.2 — IP-literal = "[" ( IPv6address / IPvFuture ) "]". The address
    // grammar is intricate enough that the standard library's parser is both
    // shorter and more trustworthy than another hand-written one.
    // §3.2.2 — the `v` of IPvFuture is case-insensitive, like the rest of the
    // grammar's literals.
    if let Some(future) = literal.strip_prefix(['v', 'V']) {
        let Some((version, address)) = future.split_once('.') else {
            return false;
        };
        return !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_hexdigit())
            && !address.is_empty()
            && address
                .bytes()
                .all(|b| is_unreserved(b) || is_sub_delim(b) || b == b':');
    }
    literal.parse::<std::net::Ipv6Addr>().is_ok()
}

/// §3.3 — a path segment is a run of `pchar`.
fn is_segment(segment: &str) -> bool {
    is_run(segment, is_pchar)
}

/// §3.4 — `query = *( pchar / "/" / "?" )`.
fn is_query(query: &str) -> bool {
    is_run(query, |b| is_pchar(b) || b == b'/' || b == b'?')
}

/// Whether every byte is allowed, counting `%XX` as one allowed unit (§2.1).
fn is_run(s: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_hexdigit());
            if !hex(bytes.next()) || !hex(bytes.next()) {
                return false;
            }
        } else if !allowed(b) {
            return false;
        }
    }
    true
}

/// §2.3 — `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`.
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// §2.2 — `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / ","
/// / ";" / "="`.
const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// §3.3 — `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`.
const fn is_pchar(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || matches!(b, b':' | b'@')
}
