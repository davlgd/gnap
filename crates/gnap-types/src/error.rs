//! Error responses — RFC 9635 §3.6 and RFC 9767 §3.5.

use gnap_registry::ErrorCode;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// An error, as a bare code or as a code with a description.
///
/// §3.6 declares the two forms equivalent: `"error": "user_denied"` and
/// `"error": {"code": "user_denied", "description": "..."}`. The description
/// is for the developer, not for the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnapError {
    /// The error code.
    pub code: ErrorCode,

    /// A description intended for the client developer.
    pub description: Option<String>,
}

impl GnapError {
    /// An error reduced to its code.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            description: None,
        }
    }

    /// An error carrying a description.
    pub fn with_description(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
        }
    }
}

impl fmt::Display for GnapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(d) => write!(f, "{}: {d}", self.code),
            None => write!(f, "{}", self.code),
        }
    }
}

impl std::error::Error for GnapError {}

impl Serialize for GnapError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match &self.description {
            // With no description the string form is the most compact, and
            // §3.6 declares it functionally equivalent.
            None => s.serialize_str(self.code.as_str()),
            Some(d) => {
                use serde::ser::SerializeMap;
                let mut m = s.serialize_map(Some(2))?;
                m.serialize_entry("code", &self.code)?;
                m.serialize_entry("description", d)?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for GnapError {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = GnapError;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "error: a code, or an object carrying `code`")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<GnapError, E> {
                Ok(GnapError::new(ErrorCode::from(v)))
            }

            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<GnapError, M::Error> {
                #[derive(Deserialize)]
                struct Raw {
                    code: ErrorCode,
                    #[serde(default)]
                    description: Option<String>,
                }
                let r: Raw = Deserialize::deserialize(de::value::MapAccessDeserializer::new(m))
                    .map_err(|e| {
                        de::Error::custom(format!(
                            "error: {e} — the `code` field is required (RFC 9635 §3.6)"
                        ))
                    })?;
                Ok(GnapError {
                    code: r.code,
                    description: r.description,
                })
            }
        }
        d.deserialize_any(V)
    }
}
