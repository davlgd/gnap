//! The JWS Compact Serialization (RFC 7515 §7.1), bounded before decoding,
//! and the protected header of the GNAP profile.

use super::{JwsMethod, MAX_JWS_HEADER_BYTES, MAX_JWS_SIGNATURE_BYTES};
use crate::jwk::MAX_KEY_ID_BYTES;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use core::fmt;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// What a JWS asserts about itself: an ordinary proof, or the inner proof of
/// a key rotation (RFC 9635 §7.3.3.1, §7.3.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Binding,
    Rotation,
}

/// The `typ` the RFC requires for a method and a role.
///
/// The encoded headers of the RFC examples read `gnap-binding+jwsd`; the
/// normative text and the registered media types use the hyphen, and only
/// the hyphenated values are accepted.
pub(super) const fn typ(method: JwsMethod, role: Role) -> &'static str {
    match (method, role) {
        (JwsMethod::Jws, Role::Binding) => "gnap-binding-jws",
        (JwsMethod::Jwsd, Role::Binding) => "gnap-binding-jwsd",
        (JwsMethod::Jws, Role::Rotation) => "gnap-binding-rotation-jws",
        (JwsMethod::Jwsd, Role::Rotation) => "gnap-binding-rotation-jwsd",
    }
}

/// The three segments of a compact JWS, each still encoded.
#[derive(Debug, Clone, Copy)]
pub(super) struct Segments<'a> {
    pub(super) protected: &'a str,
    pub(super) payload: &'a str,
    pub(super) signature: &'a str,
}

impl<'a> Segments<'a> {
    /// Splits a compact JWS into exactly three segments, refusing a header or
    /// a signature longer than the bounds before decoding either.
    pub(super) fn split(compact: &'a str) -> Result<Self, String> {
        let mut parts = compact.split('.');
        let (Some(protected), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("a compact JWS has exactly three segments".into());
        };
        if protected.is_empty() || protected.len() > encoded_len(MAX_JWS_HEADER_BYTES) {
            return Err("the JWS protected header is empty or too long".into());
        }
        if signature.is_empty() || signature.len() > encoded_len(MAX_JWS_SIGNATURE_BYTES) {
            return Err("the JWS signature is empty or too long".into());
        }
        Ok(Self {
            protected,
            payload,
            signature,
        })
    }

    /// The JWS Signing Input: the two first segments, joined by a period.
    pub(super) fn signing_input(&self) -> String {
        format!("{}.{}", self.protected, self.payload)
    }
}

/// The length of the unpadded base64url encoding of `bytes` octets.
pub(super) const fn encoded_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

/// Decodes a segment, which must be canonical unpadded base64url.
pub(super) fn decode(segment: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| format!("the JWS {what} isn't unpadded base64url"))
}

/// Encodes bytes as unpadded base64url.
pub(super) fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The protected header of a GNAP JWS proof (RFC 9635 §7.3.3, §7.3.4).
///
/// The profile is closed: any member other than these seven is refused, so
/// that `crit`, `b64`, and the members that carry or point to a key (`jwk`,
/// `jku`, `x5c`, `x5u`, `x5t`) never reach the verifier, even when `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) alg: String,
    pub(super) kid: Option<String>,
    pub(super) typ: String,
    pub(super) htm: String,
    pub(super) uri: String,
    pub(super) created: u64,
    pub(super) ath: Option<String>,
}

impl Header {
    /// Parses a decoded protected header, refusing duplicate and unknown
    /// members, and members of the wrong JSON type.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let UniqueObject(members) = serde_json::from_slice(bytes)
            .map_err(|e| format!("the JWS protected header isn't a JSON object: {e}"))?;
        let mut header = PartialHeader::default();
        for (name, value) in members {
            match name.as_str() {
                "alg" => header.alg = Some(string(value, "alg")?),
                "kid" => header.kid = Some(string(value, "kid")?),
                "typ" => header.typ = Some(string(value, "typ")?),
                "htm" => header.htm = Some(string(value, "htm")?),
                "uri" => header.uri = Some(string(value, "uri")?),
                "ath" => header.ath = Some(string(value, "ath")?),
                "created" => {
                    header.created = Some(value.as_u64().ok_or(
                        "the JWS created member must be a nonnegative integer of seconds",
                    )?);
                }
                other => return Err(format!("the JWS header member {other} isn't supported")),
            }
        }
        let missing = |name: &str| format!("the JWS protected header lacks {name}");
        let header = Self {
            alg: header.alg.ok_or_else(|| missing("alg"))?,
            kid: header.kid,
            typ: header.typ.ok_or_else(|| missing("typ"))?,
            htm: header.htm.ok_or_else(|| missing("htm"))?,
            uri: header.uri.ok_or_else(|| missing("uri"))?,
            created: header.created.ok_or_else(|| missing("created"))?,
            ath: header.ath,
        };
        if header
            .kid
            .as_ref()
            .is_some_and(|kid| kid.is_empty() || kid.len() > MAX_KEY_ID_BYTES)
        {
            return Err(format!(
                "the JWS kid must hold 1 to {MAX_KEY_ID_BYTES} bytes"
            ));
        }
        Ok(header)
    }

    /// The header as the JSON object a signer encodes.
    pub(super) fn to_json(&self) -> Vec<u8> {
        let mut object = Map::new();
        object.insert("alg".into(), self.alg.clone().into());
        if let Some(kid) = &self.kid {
            object.insert("kid".into(), kid.clone().into());
        }
        object.insert("typ".into(), self.typ.clone().into());
        object.insert("htm".into(), self.htm.clone().into());
        object.insert("uri".into(), self.uri.clone().into());
        object.insert("created".into(), self.created.into());
        if let Some(ath) = &self.ath {
            object.insert("ath".into(), ath.clone().into());
        }
        Value::Object(object).to_string().into_bytes()
    }
}

#[derive(Default)]
struct PartialHeader {
    alg: Option<String>,
    kid: Option<String>,
    typ: Option<String>,
    htm: Option<String>,
    uri: Option<String>,
    created: Option<u64>,
    ath: Option<String>,
}

fn string(value: Value, name: &str) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value),
        _ => Err(format!("the JWS {name} member must be a string")),
    }
}

/// A JSON object whose member names are unique: RFC 7515 §5.2 has a
/// recipient either refuse duplicates or keep the last, and keeping the last
/// would let two parsers disagree on what was signed.
struct UniqueObject(Map<String, Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique member names")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut object = Map::new();
                while let Some((name, value)) = input.next_entry::<String, Value>()? {
                    if object.insert(name, value).is_some() {
                        return Err(A::Error::custom("duplicate member"));
                    }
                }
                Ok(UniqueObject(object))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
