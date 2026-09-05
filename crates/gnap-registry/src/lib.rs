//! IANA registries for the GNAP protocol.
//!
//! The 23 registries established by RFC [9635] and RFC [9767] are vendored as
//! CSV files and turned into code by `tools/generate_registry.py`. Two shapes
//! come out of it:
//!
//! - **value registries** (a value travels inside a message) become an enum
//!   carrying an [`Unregistered`] variant;
//! - **field-name registries** become a slice of `&str`.
//!
//! # Why `Unregistered` rather than an error
//!
//! GNAP is designed to be extended: Appendix D of RFC 9635 expects new values
//! to be registered over time. Rejecting an unknown value at parse time would
//! make this library obsolete on every new registration. The value is kept
//! verbatim instead, and the caller decides what to do with it:
//!
//! ```
//! use gnap_registry::KeyProofingMethod;
//!
//! let known = KeyProofingMethod::from("httpsig");
//! assert!(known.is_registered());
//!
//! let future = KeyProofingMethod::from("quantum-sig");
//! assert!(!future.is_registered());
//! assert_eq!(future.as_str(), "quantum-sig");
//! ```
//!
//! [9635]: https://www.rfc-editor.org/rfc/rfc9635
//! [9767]: https://www.rfc-editor.org/rfc/rfc9767
//! [`Unregistered`]: KeyProofingMethod::Unregistered

/// Implements the traits shared by every registry enum.
///
/// Serialization always emits the on-the-wire value, `Unregistered` included:
/// a value that is not registered is relayed unaltered.
#[macro_export]
#[doc(hidden)]
macro_rules! impl_registry_traits {
    ($t:ty) => {
        impl From<String> for $t {
            fn from(s: String) -> Self {
                Self::from(s.as_str())
            }
        }

        impl core::str::FromStr for $t {
            type Err = core::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self::from(s))
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl serde::de::Visitor<'_> for V {
                    type Value = $t;
                    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                        write!(f, concat!(stringify!($t), ": a string"))
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$t, E> {
                        Ok(<$t>::from(v))
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

mod generated;
pub use generated::*;

/// How many GNAP registries each RFC establishes.
///
/// Note: §5 of RFC 9767 announces "created five registries" while it actually
/// creates seven. See the project's local errata list, entry E6.
pub const REGISTRY_COUNT_RFC9635: usize = 16;
/// See [`REGISTRY_COUNT_RFC9635`].
pub const REGISTRY_COUNT_RFC9767: usize = 7;

/// Reports whether a field name appears in a given registry.
///
/// Useful to decide what to do with an extension field: Appendix D of RFC 9635
/// allows a recipient either to ignore it or to reject it.
///
/// ```
/// use gnap_registry::{is_registered_field, GRANT_REQUEST_PARAMETERS};
///
/// assert!(is_registered_field(GRANT_REQUEST_PARAMETERS, "access_token"));
/// assert!(!is_registered_field(GRANT_REQUEST_PARAMETERS, "x_custom"));
/// ```
#[must_use]
pub fn is_registered_field(registry: &[&str], name: &str) -> bool {
    registry.contains(&name)
}
