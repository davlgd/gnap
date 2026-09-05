//! Tools for GNAP's eight polymorphic fields.
//!
//! Appendix E of RFC 9635 embraces polymorphism: one field accepts two JSON
//! types that express the same thing at different levels of detail.
//!
//! `#[serde(untagged)]` is ruled out. Measured, not assumed: on a nested error
//! it reports at the outer enum and loses the offending field, and it silently
//! accepts several RFC violations. So every polymorphic field gets its own
//! visitor.
//!
//! # Reading a field that arrived either way
//!
//! ```
//! use gnap_types::client::Client;
//!
//! // §2.3.1 — the client sent an instance identifier instead of its details.
//! let by_reference: Client = serde_json::from_str(r#""client-541-ab""#).unwrap();
//! assert_eq!(by_reference.as_reference(), Some("client-541-ab"));
//! assert!(by_reference.as_value().is_none());
//!
//! // §2.3 — or it sent them in full.
//! let by_value: Client =
//!     serde_json::from_str(r#"{"key":{"proof":"httpsig","cert":"MIIC…"}}"#).unwrap();
//! assert!(by_value.as_reference().is_none());
//! assert_eq!(by_value.as_value().unwrap().key.as_value().unwrap().proof.method().as_str(), "httpsig");
//! ```

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Declares an "object, or reference string" type.
///
/// This is the shape of `client` (§2.3), `user` (§2.4) and `key` (§7.1): the
/// full value, or an opaque reference the recipient knows how to resolve.
#[macro_export]
macro_rules! object_or_reference {
    ($(#[$meta:meta])* $name:ident, $object:ty, $field:literal) => {
        $(#[$meta])*
        // Eq is not derivable: every object this macro wraps carries a
        // serde_json::Map for its extension fields, and Value is not Eq
        // because of floats. Clippy sees the macro, not its expansions.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Debug, Clone, PartialEq)]
        pub enum $name {
            /// The value, sent in full.
            ByValue(Box<$object>),
            /// An opaque reference for the recipient.
            ByReference(String),
        }

        impl $name {
            /// The reference, when the value was sent in that form.
            pub fn as_reference(&self) -> Option<&str> {
                match self {
                    Self::ByReference(r) => Some(r.as_str()),
                    Self::ByValue(_) => None,
                }
            }

            /// The value, when it was sent in full.
            pub fn as_value(&self) -> Option<&$object> {
                match self {
                    Self::ByValue(v) => Some(v),
                    Self::ByReference(_) => None,
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                match self {
                    Self::ByValue(v) => v.serialize(s),
                    Self::ByReference(r) => s.serialize_str(r),
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = $name;

                    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                        write!(f, concat!($field, ": an object, or a string (reference)"))
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        if v.is_empty() {
                            return Err(E::custom(concat!(
                                $field, ": a reference cannot be empty"
                            )));
                        }
                        Ok($name::ByReference(v.to_owned()))
                    }

                    fn visit_map<M: serde::de::MapAccess<'de>>(
                        self, m: M,
                    ) -> Result<$name, M::Error> {
                        // Inner errors surface as they are, instead of being
                        // swallowed by a fallback to the other variant.
                        serde::Deserialize::deserialize(
                            serde::de::value::MapAccessDeserializer::new(m),
                        )
                        .map(|v| $name::ByValue(Box::new(v)))
                    }
                }
                d.deserialize_any(V)
            }
        }
    };
}

/// A named method, optionally carrying parameters.
///
/// Shared by `proof` (§7.3) and the interaction start modes (§2.5.1): the
/// string form names the method with its defaults, the object form spells out
/// the parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodOrObject<T> {
    /// The method alone, with default parameters.
    Named(T),
    /// The method and its parameters.
    Detailed {
        /// The method name.
        method: T,
        /// The object's other members, kept as they are.
        ///
        /// GNAP is extensible (Appendix D): dropping unknown parameters would
        /// prevent relaying an extension one does not understand.
        params: serde_json::Map<String, serde_json::Value>,
    },
}

impl<T> MethodOrObject<T> {
    /// The method name, whichever form was used.
    pub const fn method(&self) -> &T {
        match self {
            Self::Named(m) | Self::Detailed { method: m, .. } => m,
        }
    }

    /// A parameter, when the object form was used.
    ///
    /// §7.3.1 defines the object form of `proof` with `alg` and
    /// `content-digest-alg`; this is how those are read.
    ///
    /// ```
    /// use gnap_types::key::KeyObject;
    ///
    /// let key: KeyObject = serde_json::from_str(
    ///     r#"{"proof":{"method":"httpsig","alg":"ecdsa-p384-sha384",
    ///                  "content-digest-alg":"sha-512"},
    ///         "cert":"MIIC…"}"#,
    /// ).unwrap();
    ///
    /// assert_eq!(key.proof.method().as_str(), "httpsig");
    /// assert_eq!(key.proof.param("alg").unwrap(), "ecdsa-p384-sha384");
    /// assert!(key.proof.param("absent").is_none());
    ///
    /// // The string form carries no parameters at all.
    /// let plain: KeyObject =
    ///     serde_json::from_str(r#"{"proof":"httpsig","cert":"MIIC…"}"#).unwrap();
    /// assert!(plain.proof.param("alg").is_none());
    /// ```
    pub fn param(&self, name: &str) -> Option<&serde_json::Value> {
        match self {
            Self::Named(_) => None,
            Self::Detailed { params, .. } => params.get(name),
        }
    }
}

impl<T: Serialize> Serialize for MethodOrObject<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Named(m) => m.serialize(s),
            Self::Detailed { method, params } => {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(params.len() + 1))?;
                map.serialize_entry("method", method)?;
                for (k, v) in params {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de, T> Deserialize<'de> for MethodOrObject<T>
where
    T: From<String>,
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(std::marker::PhantomData<T>);

        impl<'de, T: From<String>> Visitor<'de> for V<T> {
            type Value = MethodOrObject<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a method name, or an object containing `method`")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(MethodOrObject::Named(T::from(v.to_owned())))
            }

            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<Self::Value, M::Error> {
                let mut obj: serde_json::Map<String, serde_json::Value> =
                    Deserialize::deserialize(de::value::MapAccessDeserializer::new(m))?;
                let method = obj
                    .remove("method")
                    .ok_or_else(|| de::Error::custom("the `method` field is required"))?;
                let method = method
                    .as_str()
                    .ok_or_else(|| de::Error::custom("`method`: expected a string"))?;
                Ok(MethodOrObject::Detailed {
                    method: T::from(method.to_owned()),
                    params: obj,
                })
            }
        }

        d.deserialize_any(V(std::marker::PhantomData))
    }
}
