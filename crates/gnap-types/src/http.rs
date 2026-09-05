//! HTTP request and response shapes.
//!
//! These describe messages, they do not move them: no I/O happens here. They
//! live in this crate because both roles need the same vocabulary — a client
//! builds a request an authorization server reads, and the two must agree on
//! byte order and header order because the signature covers them.

/// An HTTP request, as bytes on the way out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method, uppercase by convention.
    pub method: String,
    /// The absolute request URI.
    pub url: String,
    /// Header fields, in the order they should be sent.
    pub headers: Vec<(String, String)>,
    /// The body, when there is one.
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// A request with no headers and no body.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Adds a header field.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets a JSON body and its `Content-Type`.
    #[must_use]
    pub fn json_body(mut self, body: Vec<u8>) -> Self {
        self.headers
            .push(("Content-Type".into(), "application/json".into()));
        self.body = Some(body);
        self
    }

    /// The first value of a header field, matched case-insensitively.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.header_values(name).next()
    }

    /// Every value of a header field, in message order, matched
    /// case-insensitively.
    ///
    /// A signature that covers a field covers all of its instances, joined
    /// (RFC 9421 §2.1); reading only the first would verify a different
    /// message from the one that was sent.
    pub fn header_values(&self, name: &str) -> impl Iterator<Item = &str> {
        header_values(&self.headers, name)
    }

    /// The field's instances combined into the one value a signature covers
    /// (RFC 9421 §2.1).
    ///
    /// Each instance is stripped of leading and trailing whitespace and the
    /// list is joined with a single comma and a single space. `None` when the
    /// field is absent. `Authorization` is not a list field and must not be
    /// combined this way; a request carrying it twice is malformed.
    #[must_use]
    pub fn combined_header_value(&self, name: &str) -> Option<String> {
        combined_header_value(&self.headers, name)
    }
}

/// Every instance of `name` in `headers`, matched case-insensitively.
fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &str,
) -> impl Iterator<Item = &'a str> + 'a {
    let name = name.to_ascii_lowercase();
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(&name))
        .map(|(_, v)| v.as_str())
}

/// RFC 9421 §2.1: instances trimmed of SP and HTAB, joined by `, `.
fn combined_header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = header_values(headers, name)
        .map(|v| v.trim_matches([' ', '\t']))
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// An HTTP response, as bytes on the way in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Header fields.
    pub headers: Vec<(String, String)>,
    /// The body, possibly empty.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value of a header field, matched case-insensitively.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.header_values(name).next()
    }

    /// Every value of a header field, in message order, matched
    /// case-insensitively.
    pub fn header_values(&self, name: &str) -> impl Iterator<Item = &str> {
        header_values(&self.headers, name)
    }

    /// The field's instances combined as RFC 9421 §2.1 does; see
    /// [`HttpRequest::combined_header_value`].
    #[must_use]
    pub fn combined_header_value(&self, name: &str) -> Option<String> {
        combined_header_value(&self.headers, name)
    }

    /// Whether the AS sent `Cache-Control: no-store`, which §3 requires of it.
    ///
    /// A client cannot force the AS to comply, but it can notice that it did
    /// not — which is exactly what a conformance check wants.
    ///
    /// `no-store` has to be a directive of its own (RFC 9111 §5.2): the field
    /// is a comma-separated list, directive names are case-insensitive, and a
    /// directive may carry a quoted argument. So `x-no-store` is not it, and
    /// neither is `foo="no-store"` — a substring search would take both.
    #[must_use]
    pub fn has_no_store(&self) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
            .flat_map(|(_, v)| split_directives(v))
            .any(|directive| {
                directive
                    .split_once('=')
                    .map_or(directive, |(name, _)| name)
                    .trim()
                    .eq_ignore_ascii_case("no-store")
            })
    }
}

/// Splits a `Cache-Control` value on the commas that sit outside a
/// quoted-string, since a directive argument may hold one (RFC 9111 §5.2,
/// RFC 9110 §5.6.4).
fn split_directives(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out
}
