//! Access rights — RFC 9635 §8.

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// One access right: an opaque reference, or a structured description.
///
/// The total access a token carries is the union of every array element (§8).
/// Both forms mix freely inside one array (§8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessItem {
    /// An opaque reference known to the AS (§8.1).
    ///
    /// Plays the role of OAuth 2.0's `scope`, without its character
    /// restrictions.
    Reference(String),

    /// A right described by its dimensions (§8).
    Described(Box<AccessObject>),
}

/// The dimensions of an access right (§8).
///
/// GNAP mandates only `type`; the other fields are reusable components an API
/// designer may or may not use. The access requested is the cross product of
/// the dimensions present.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccessObject {
    /// The API type. Required.
    ///
    /// Compared by exact byte match, with no normalization (§8).
    #[serde(rename = "type")]
    pub kind: String,

    /// The actions the client intends to perform.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub actions: Option<Vec<String>>,

    /// The locations of the RS.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub locations: Option<Vec<String>>,

    /// The kinds of data targeted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub datatypes: Option<Vec<String>>,

    /// A specific resource at the RS.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identifier: Option<String>,

    /// The privilege levels requested.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub privileges: Option<Vec<String>>,

    /// API-specific fields, kept as they are.
    ///
    /// §8 states that `type` decides which other fields are allowed; dropping
    /// them would prevent relaying an API one does not know.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AccessItem {
    /// The `type`, when the right is described in structured form.
    #[must_use]
    pub fn kind(&self) -> Option<&str> {
        match self {
            Self::Described(o) => Some(o.kind.as_str()),
            Self::Reference(_) => None,
        }
    }
}

impl Serialize for AccessItem {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Reference(r) => s.serialize_str(r),
            Self::Described(o) => o.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for AccessItem {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AccessItem;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "access[]: a reference (string), or an object carrying `type`"
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<AccessItem, E> {
                Ok(AccessItem::Reference(v.to_owned()))
            }

            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<AccessItem, M::Error> {
                let o: AccessObject = Deserialize::deserialize(
                    de::value::MapAccessDeserializer::new(m),
                )
                .map_err(|e| {
                    de::Error::custom(format!(
                        "access[]: {e} — the `type` field is required (RFC 9635 §8)"
                    ))
                })?;
                Ok(AccessItem::Described(Box::new(o)))
            }
        }
        d.deserialize_any(V)
    }
}
