//! A per-session record of the requests the lab's client attempts, for the
//! page's exchange inspector.
//!
//! The record holds closed values only: enums, numbers, and names from fixed
//! catalogues. No string from a request or a response is copied into it, so
//! neither a token, a nonce, a handle, a signature, nor an error description
//! can reach the page through it, whatever the exchange carries.

use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use gnap_crypto::httpsig::{
    parse_covered_components, parse_signature_params, parse_signatures, Component,
};
use gnap_registry::ErrorCode;
use serde::Serialize;
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Most attempts kept per session; later ones are only counted.
pub(super) const MAX_TRACE: usize = 64;
/// Most tokens described in one body, the lab's most per request; the
/// others are counted.
pub(super) const MAX_TOKENS_SHOWN: usize = 2;
/// Most rights described per token; the others are counted.
pub(super) const MAX_RIGHTS_SHOWN: usize = 4;
/// Most header fields examined in one message; a longer list isn't parsed.
pub(super) const MAX_HEADERS: usize = 64;
/// Longest header field value examined, in bytes; a longer one isn't parsed.
pub(super) const MAX_FIELD_BYTES: usize = 4096;
/// Largest body parsed, in bytes; a larger one is only reported as such.
pub(super) const MAX_PARSED_BODY: usize = 16 * 1024;
/// Deepest JSON nesting accepted in a parsed body.
pub(super) const MAX_JSON_DEPTH: usize = 16;

/// The servers the client reaches. The metadata server behind the documents
/// server is never called by the client, so it has no entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Party {
    AuthorizationServer,
    DocumentsServer,
    ReportsServer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Route {
    Grant,
    Continue,
    TokenManagement,
    Folder,
    Archive,
    FolderMetadata,
    Reports,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Method {
    Get,
    Post,
    Patch,
    Delete,
    Options,
    Other,
}

/// The proof a request announces. Nothing here is verified: it is what the
/// request's fields declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AnnouncedProof {
    Httpsig,
    Jws,
    Jwsd,
    /// Several proof fields, or several of one kind.
    Ambiguous,
    /// A proof field that doesn't parse, or is past the parsing bounds.
    Unparsable,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Covered {
    #[serde(rename = "@method")]
    Method,
    #[serde(rename = "@target-uri")]
    TargetUri,
    ContentDigest,
    ContentType,
    ContentLength,
    Authorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SignatureAlg {
    RsaPssSha512,
    EcdsaP256Sha256,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum DigestAlg {
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-512")]
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MediaType {
    Json,
    Jose,
    Other,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BodyKind {
    Empty,
    Object,
    Array,
    Scalar,
    /// A JOSE serialization, which the record doesn't decode.
    Jose,
    NotJson,
    TooLarge,
    TooDeep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FieldName {
    AccessToken,
    Client,
    Continue,
    Error,
    InstanceId,
    Interact,
    InteractRef,
    Subject,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JsonKind {
    Object,
    Array,
    String,
    Number,
    Bool,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Label {
    Documents,
    Reports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) enum Right {
    #[serde(rename = "synthetic-folder:read")]
    Folder,
    #[serde(rename = "synthetic-archive:read")]
    Archive,
    #[serde(rename = "synthetic-reports:read")]
    Reports,
    #[serde(rename = "archive-metadata:read")]
    Metadata,
}

impl Right {
    /// The right a string names, when it is one of the lab's own.
    fn named(value: &str) -> Option<Self> {
        [
            (super::FOLDER_READ, Self::Folder),
            (super::ARCHIVE_READ, Self::Archive),
            (super::multiple::REPORTS_READ, Self::Reports),
            (super::derivation::METADATA_READ, Self::Metadata),
        ]
        .into_iter()
        .find_map(|(name, right)| (name == value).then_some(right))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Field {
    pub name: FieldName,
    pub kind: JsonKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct TokenShape {
    pub label: Option<Label>,
    /// A label the record doesn't name.
    pub other_label: bool,
    pub rights: Vec<Right>,
    pub other_rights: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Shape {
    pub kind: BodyKind,
    pub fields: Vec<Field>,
    pub other_fields: u16,
    pub tokens: Vec<TokenShape>,
    pub more_tokens: u16,
    /// A registered GNAP error code, from the registry's own list.
    pub error: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct RequestSummary {
    pub to: Party,
    pub route: Route,
    pub method: Method,
    pub proof: AnnouncedProof,
    pub covered: Vec<Covered>,
    pub other_components: u16,
    pub alg: Option<SignatureAlg>,
    pub gnap_authorization: bool,
    pub digests: Vec<DigestAlg>,
    /// A `Content-Digest` field that doesn't parse as a Dictionary of Byte
    /// Sequences, so no algorithm is named from it.
    pub digest_unparsable: bool,
    pub body: Shape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Outcome {
    Response {
        status: u16,
        media: Option<MediaType>,
        body: Shape,
    },
    /// The transport returned no response: whether the request even left
    /// isn't known at this level.
    NoResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Attempt {
    pub seq: u16,
    pub request: RequestSummary,
    pub outcome: Outcome,
}

/// The attempts of one session, at most [`MAX_TRACE`] of them.
#[derive(Debug, Default, Serialize)]
pub(super) struct Trace {
    attempts: Vec<Attempt>,
    /// Attempts made once the trace was full.
    dropped: u16,
}

impl Trace {
    fn is_full(&self) -> bool {
        self.attempts.len() >= MAX_TRACE
    }

    fn record(&mut self, request: Option<RequestSummary>, outcome: Option<Outcome>) {
        match (request, outcome) {
            (Some(request), Some(outcome)) if !self.is_full() => {
                let seq = u16::try_from(self.attempts.len()).unwrap_or(u16::MAX);
                self.attempts.push(Attempt {
                    seq,
                    request,
                    outcome,
                });
            }
            _ => self.dropped = self.dropped.saturating_add(1),
        }
    }
}

/// The record a session shares with the transports that write into it.
pub(super) type SharedTrace = Arc<Mutex<Trace>>;

/// A transport that records, into its session's trace, a summary of each
/// request it forwards and of the response. Recording never changes what the
/// inner transport returns: a full or poisoned trace loses the entry, not the
/// exchange.
pub(super) struct Recording<T> {
    inner: T,
    origin: String,
    trace: SharedTrace,
}

impl<T> Recording<T> {
    pub(super) const fn new(inner: T, origin: String, trace: SharedTrace) -> Self {
        Self {
            inner,
            origin,
            trace,
        }
    }
}

impl<T: HttpTransport> HttpTransport for Recording<T> {
    type Error = T::Error;

    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        // The summary is taken before the request moves, and the lock is not
        // held while the network works.
        let full = self.trace.lock().map_or(true, |trace| trace.is_full());
        let summary = (!full).then(|| summarize_request(&request, &self.origin));
        let result = self.inner.send(request);
        let outcome = (!full).then(|| match &result {
            Ok(response) => summarize_response(response),
            Err(_) => Outcome::NoResponse,
        });
        if let Ok(mut trace) = self.trace.lock() {
            trace.record(summary, outcome);
        }
        result
    }
}

/// What a request says about itself, in closed values.
pub(super) fn summarize_request(request: &HttpRequest, origin: &str) -> RequestSummary {
    let (to, route) = destination(&request.url, origin);
    let headers = Headers::of(&request.headers);
    let (proof, covered, other_components, alg) = announced_proof(&headers);
    let jose = headers.media() == Some(MediaType::Jose);
    let digest = match headers.all("content-digest").as_deref() {
        Some([]) => Ok(Vec::new()),
        Some([value]) => digests(value),
        None | Some(_) => Err(()),
    };
    RequestSummary {
        to,
        route,
        method: method(&request.method),
        proof,
        covered,
        other_components,
        alg,
        gnap_authorization: headers.one("authorization").is_some_and(gnap_scheme),
        digests: digest.clone().unwrap_or_default(),
        digest_unparsable: digest.is_err(),
        body: shape(request.body.as_deref(), jose),
    }
}

/// What a response says, in closed values.
pub(super) fn summarize_response(response: &HttpResponse) -> Outcome {
    let headers = Headers::of(&response.headers);
    let media = headers.media();
    let body = shape(Some(&response.body), media == Some(MediaType::Jose));
    Outcome::Response {
        status: response.status,
        media,
        body,
    }
}

/// The server and route a URL reaches, when it is the lab's own origin and one
/// of its exact paths.
fn destination(url: &str, origin: &str) -> (Party, Route) {
    let unknown = (Party::Unknown, Route::Unknown);
    let Some(path) = url.strip_prefix(origin) else {
        return unknown;
    };
    match path {
        "/gnap" => (Party::AuthorizationServer, Route::Grant),
        "/continue" => (Party::AuthorizationServer, Route::Continue),
        "/resource/folder" => (Party::DocumentsServer, Route::Folder),
        "/resource/archive" => (Party::DocumentsServer, Route::Archive),
        p if p == super::derivation::RS1_PATH => (Party::DocumentsServer, Route::FolderMetadata),
        p if p == super::multiple::REPORTS_PATH => (Party::ReportsServer, Route::Reports),
        p => match p.strip_prefix("/token/") {
            // One path segment of URL-safe characters: a management handle.
            Some(handle)
                if !handle.is_empty()
                    && handle.len() <= 128
                    && handle
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
            {
                (Party::AuthorizationServer, Route::TokenManagement)
            }
            _ => unknown,
        },
    }
}

fn method(method: &str) -> Method {
    match method {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        "OPTIONS" => Method::Options,
        _ => Method::Other,
    }
}

/// A message's header fields, examined only within the parsing bounds.
struct Headers<'a> {
    fields: Option<&'a [(String, String)]>,
}

impl<'a> Headers<'a> {
    fn of(fields: &'a [(String, String)]) -> Self {
        let bounded = fields.len() <= MAX_HEADERS
            && fields
                .iter()
                .all(|(_, value)| value.len() <= MAX_FIELD_BYTES);
        Self {
            fields: bounded.then_some(fields),
        }
    }

    /// The values of a field, or `None` past the parsing bounds.
    fn all(&self, name: &str) -> Option<Vec<&'a str>> {
        self.fields.map(|fields| {
            fields
                .iter()
                .filter(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect()
        })
    }

    /// The one value of a field present exactly once.
    fn one(&self, name: &str) -> Option<&'a str> {
        match self.all(name)?.as_slice() {
            [value] => Some(value),
            _ => None,
        }
    }

    fn media(&self) -> Option<MediaType> {
        let values = self.all("content-type")?;
        match values.as_slice() {
            [] => None,
            [value] => {
                let essence = value.split(';').next().unwrap_or_default().trim();
                Some(if essence.eq_ignore_ascii_case("application/json") {
                    MediaType::Json
                } else if essence.eq_ignore_ascii_case("application/jose") {
                    MediaType::Jose
                } else {
                    MediaType::Other
                })
            }
            _ => Some(MediaType::Ambiguous),
        }
    }
}

type Proof = (AnnouncedProof, Vec<Covered>, u16, Option<SignatureAlg>);

/// The proof the fields announce, and for an HTTP signature, what it covers.
fn announced_proof(headers: &Headers<'_>) -> Proof {
    let unparsable = (AnnouncedProof::Unparsable, Vec::new(), 0, None);
    let (Some(inputs), Some(signatures), Some(detached)) = (
        headers.all("signature-input"),
        headers.all("signature"),
        headers.all("detached-jws"),
    ) else {
        return unparsable;
    };
    let Some(types) = headers.all("content-type") else {
        return unparsable;
    };
    let jose = types
        .iter()
        .filter(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/jose")
        })
        .count();
    if jose > 0 && types.len() > 1 {
        return (AnnouncedProof::Ambiguous, Vec::new(), 0, None);
    }
    let attached = jose == 1;
    let kinds = usize::from(!inputs.is_empty() || !signatures.is_empty())
        + usize::from(!detached.is_empty())
        + usize::from(attached);
    match kinds {
        0 => (AnnouncedProof::None, Vec::new(), 0, None),
        1 if !detached.is_empty() => {
            let proof = if detached.len() == 1 {
                AnnouncedProof::Jwsd
            } else {
                AnnouncedProof::Ambiguous
            };
            (proof, Vec::new(), 0, None)
        }
        1 if attached => (AnnouncedProof::Jws, Vec::new(), 0, None),
        1 => match (inputs.as_slice(), signatures.as_slice()) {
            ([input], [signature]) => httpsig(input, signature).unwrap_or(unparsable),
            _ => (AnnouncedProof::Ambiguous, Vec::new(), 0, None),
        },
        _ => (AnnouncedProof::Ambiguous, Vec::new(), 0, None),
    }
}

/// An HTTP signature's covered components and algorithm, read with the SDK's
/// own structured-field parser.
fn httpsig(input: &str, signature: &str) -> Option<Proof> {
    let parsed = parse_signatures(input, signature);
    if parsed.len() > 1 {
        return Some((AnnouncedProof::Ambiguous, Vec::new(), 0, None));
    }
    let [Ok(labelled)] = parsed.as_slice() else {
        return None;
    };
    let components = parse_covered_components(&labelled.raw_params).ok()?;
    let params = parse_signature_params(&labelled.raw_params).ok()?;
    let mut covered = Vec::new();
    let mut other = 0_u16;
    for component in &components {
        let known = match component {
            Component::Method => Some(Covered::Method),
            Component::TargetUri => Some(Covered::TargetUri),
            Component::ContentDigest => Some(Covered::ContentDigest),
            Component::Authorization => Some(Covered::Authorization),
            Component::Field(name) if name == "content-type" => Some(Covered::ContentType),
            Component::Field(name) if name == "content-length" => Some(Covered::ContentLength),
            _ => None,
        };
        match known {
            Some(known) if !covered.contains(&known) => covered.push(known),
            Some(_) => {}
            None => other = other.saturating_add(1),
        }
    }
    let alg = match params.alg.as_deref() {
        Some("rsa-pss-sha512") => Some(SignatureAlg::RsaPssSha512),
        Some("ecdsa-p256-sha256") => Some(SignatureAlg::EcdsaP256Sha256),
        Some("ed25519") => Some(SignatureAlg::Ed25519),
        _ => None,
    };
    Some((AnnouncedProof::Httpsig, covered, other, alg))
}

/// The exact `GNAP` scheme, followed by a credential.
fn gnap_scheme(value: &str) -> bool {
    value
        .split_once(' ')
        .is_some_and(|(scheme, credential)| scheme == "GNAP" && !credential.trim().is_empty())
}

/// The digest algorithms a `Content-Digest` field names, read with the SDK's
/// own Dictionary parser.
fn digests(value: &str) -> Result<Vec<DigestAlg>, ()> {
    let named = gnap_crypto::content_digest_algorithms(value).map_err(|_| ())?;
    let mut found = Vec::new();
    for alg in named {
        let alg = match alg {
            gnap_crypto::DigestAlgorithm::Sha256 => DigestAlg::Sha256,
            gnap_crypto::DigestAlgorithm::Sha512 => DigestAlg::Sha512,
            _ => continue,
        };
        if !found.contains(&alg) {
            found.push(alg);
        }
    }
    Ok(found)
}

/// A body's structure: the GNAP fields it carries, and its tokens.
fn shape(body: Option<&[u8]>, jose: bool) -> Shape {
    let closed = |kind| Shape {
        kind,
        fields: Vec::new(),
        other_fields: 0,
        tokens: Vec::new(),
        more_tokens: 0,
        error: None,
    };
    let body = match body {
        None | Some([]) => return closed(BodyKind::Empty),
        Some(body) if body.len() > MAX_PARSED_BODY => return closed(BodyKind::TooLarge),
        Some(_) if jose => return closed(BodyKind::Jose),
        Some(body) => body,
    };
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return closed(BodyKind::NotJson);
    };
    if depth(&value) > MAX_JSON_DEPTH {
        return closed(BodyKind::TooDeep);
    }
    let Value::Object(object) = &value else {
        return closed(if value.is_array() {
            BodyKind::Array
        } else {
            BodyKind::Scalar
        });
    };
    let mut result = closed(BodyKind::Object);
    for (name, value) in object {
        match field_name(name) {
            Some(name) => result.fields.push(Field {
                name,
                kind: kind(value),
            }),
            None => result.other_fields = result.other_fields.saturating_add(1),
        }
    }
    result.error = object.get("error").and_then(error_code);
    if let Some(tokens) = object.get("access_token") {
        let tokens: Vec<&Value> = match tokens {
            Value::Array(tokens) => tokens.iter().collect(),
            token => vec![token],
        };
        for token in tokens.iter().take(MAX_TOKENS_SHOWN) {
            result.tokens.push(token_shape(token));
        }
        result.more_tokens =
            u16::try_from(tokens.len().saturating_sub(MAX_TOKENS_SHOWN)).unwrap_or(u16::MAX);
    }
    result
}

fn token_shape(token: &Value) -> TokenShape {
    let label = token.get("label");
    let named = match label.and_then(Value::as_str) {
        Some(super::multiple::DOCUMENTS) => Some(Label::Documents),
        Some(super::multiple::REPORTS) => Some(Label::Reports),
        _ => None,
    };
    let mut rights = Vec::new();
    let mut other_rights = 0_u16;
    for item in token
        .get("access")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match item.as_str().and_then(Right::named) {
            Some(right) if rights.len() < MAX_RIGHTS_SHOWN && !rights.contains(&right) => {
                rights.push(right);
            }
            _ => other_rights = other_rights.saturating_add(1),
        }
    }
    TokenShape {
        label: named,
        other_label: label.is_some() && named.is_none(),
        rights,
        other_rights,
    }
}

fn field_name(name: &str) -> Option<FieldName> {
    Some(match name {
        "access_token" => FieldName::AccessToken,
        "client" => FieldName::Client,
        "continue" => FieldName::Continue,
        "error" => FieldName::Error,
        "instance_id" => FieldName::InstanceId,
        "interact" => FieldName::Interact,
        "interact_ref" => FieldName::InteractRef,
        "subject" => FieldName::Subject,
        "user" => FieldName::User,
        _ => return None,
    })
}

const fn kind(value: &Value) -> JsonKind {
    match value {
        Value::Object(_) => JsonKind::Object,
        Value::Array(_) => JsonKind::Array,
        Value::String(_) => JsonKind::String,
        Value::Number(_) => JsonKind::Number,
        Value::Bool(_) => JsonKind::Bool,
        Value::Null => JsonKind::Null,
    }
}

fn depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A registered GNAP error code, as a string or an object's `code`, taken
/// from the registry's own list: an unregistered code, or a description, is
/// never copied.
fn error_code(error: &Value) -> Option<&'static str> {
    let code = error
        .as_str()
        .or_else(|| error.get("code").and_then(Value::as_str))?;
    ErrorCode::REGISTERED
        .iter()
        .copied()
        .find(|known| *known == code)
}

#[cfg(test)]
#[path = "trace_tests.rs"]
mod tests;
