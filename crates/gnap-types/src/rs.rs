//! RS-facing discovery, introspection and resource registration — RFC 9767 §3.
//!
//! Resource-server identities are deliberately distinct from client identities.
//! These types carry no authentication or token-validity decision by themselves.

use crate::access::AccessItem;
use crate::key::Key;
use crate::message::{validate_discovery_endpoint, DiscoveryError};
use crate::token::TokenValue;
use gnap_registry::{AccessTokenFlag, KeyProofingMethod, RsErrorCode, TokenFormat};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// An RS presenting a key by value or by a prearranged reference (§3.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceServerObject {
    /// The RS's key, never the requesting client instance's key.
    pub key: Key,
    /// Extensions retained for the AS to evaluate, not silently discard.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

crate::object_or_reference!(
    /// A resource server's identity, not a client-instance identity (§3.2).
    ResourceServer,
    ResourceServerObject,
    "resource_server"
);

/// The context supplied by an RS when introspecting a token (§3.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntrospectionRequest {
    /// The token presented by the client, in the body rather than Authorization.
    pub access_token: TokenValue,
    /// The RS authenticating this introspection request.
    pub resource_server: ResourceServer,
    /// The client's proof method, not the RS's signature or its parameters.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub proof: Option<KeyProofingMethod>,
    /// Minimum rights needed for the resource request, if supplied.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub access: Option<Vec<AccessItem>>,
    /// The AS must account for these parameters before reporting an active token.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A resource set submitted by its RS to the AS (RFC 9767 §3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegistrationRequest {
    /// Required rights; their meaning and ownership are deployment decisions.
    pub access: Vec<AccessItem>,
    /// The RS proving possession of its own registered key.
    pub resource_server: ResourceServer,
    /// Registered formats acceptable to the RS. Empty is not omission.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub token_formats_supported: Option<Vec<TokenFormat>>,
    /// Whether the RS expects to introspect tokens for these resources.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub token_introspection_required: Option<bool>,
    /// Extensions preserved for explicit policy handling, never stripped.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Registration result; a reference is not an access token (RFC 9767 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRegistrationResponse {
    /// Required JSON string representing the registered set, without token68 rules.
    pub resource_reference: String,
    /// Optional assigned RS identity, not a resource identifier or credential.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub instance_id: Option<String>,
    /// Optional AS endpoint where this RS can introspect tokens.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub introspection_endpoint: Option<String>,
    /// Response extensions retained for the consumer to evaluate.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The sole top-level field of an RS-facing error response (§3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsErrorResponse {
    /// Error code, optionally accompanied by a developer-facing description.
    pub error: RsError,
}

/// An RS-facing error, serialized as a string or a described object (§3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsError {
    /// A registered RS-facing error code, or a retained extension code.
    pub code: RsErrorCode,
    /// Optional diagnostic; it must not contain token values or private keys.
    pub description: Option<String>,
}

impl Serialize for RsError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !valid_error_code(self.code.as_str()) {
            return Err(serde::ser::Error::custom(
                "RS error code must be nonempty ASCII (RFC 9767 §3.5)",
            ));
        }
        if let Some(description) = &self.description {
            serde_json::json!({"code": self.code, "description": description}).serialize(serializer)
        } else {
            self.code.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RsError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = RsError;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an RS error code string or object (RFC 9767 §3.5)")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if !valid_error_code(value) {
                    return Err(de::Error::custom(
                        "RS error code must be nonempty ASCII (RFC 9767 §3.5)",
                    ));
                }
                Ok(RsError {
                    code: value.parse().map_err(de::Error::custom)?,
                    description: None,
                })
            }
            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Object {
                    code: RsErrorCode,
                    #[serde(default)]
                    description: Option<String>,
                }
                let object = Object::deserialize(de::value::MapAccessDeserializer::new(map))?;
                if !valid_error_code(object.code.as_str()) {
                    return Err(de::Error::custom(
                        "RS error code must be nonempty ASCII (RFC 9767 §3.5)",
                    ));
                }
                Ok(RsError {
                    code: object.code,
                    description: object.description,
                })
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

const fn valid_error_code(code: &str) -> bool {
    !code.is_empty() && code.is_ascii()
}

/// An RS-facing AS discovery document (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsDiscovery {
    /// The same exact grant endpoint that client instances use.
    pub grant_request_endpoint: String,
    /// Present only when introspection is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// Registered formats only; opaque reference tokens have no registered name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_formats_supported: Option<Vec<TokenFormat>>,
    /// Present only when dynamic resource registration is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_registration_endpoint: Option<String>,
    /// Key-proofing methods actually supported by this AS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_proofs_supported: Option<Vec<KeyProofingMethod>>,
    /// Discovery extensions are retained for consumers.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl RsDiscovery {
    /// The well-known URL, preserving the grant endpoint's scheme and authority.
    ///
    /// All advertised endpoints must be HTTPS URLs with hosts and no fragments.
    /// # Errors
    /// Returns an error for a malformed or non-HTTPS endpoint.
    pub fn discovery_url(&self) -> Result<String, DiscoveryError> {
        self.checked_url(false)
    }

    /// Explicit HTTP-loopback development deviation, not RFC 9767 conformance.
    ///
    /// # Errors
    /// Rejects malformed endpoints and HTTP on non-loopback hosts.
    pub fn discovery_url_for_local_development(&self) -> Result<String, DiscoveryError> {
        self.checked_url(true)
    }

    fn checked_url(&self, local: bool) -> Result<String, DiscoveryError> {
        // RFC 9767 §3.1: "at the URL with the same schema and authority as
        // the grant request endpoint URL, at the path /.well-known/gnap-as-rs."
        for endpoint in std::iter::once(&self.grant_request_endpoint)
            .chain(self.introspection_endpoint.iter())
            .chain(self.resource_registration_endpoint.iter())
        {
            validate_discovery_endpoint(endpoint, local)?;
        }
        let (scheme, rest) = self
            .grant_request_endpoint
            .split_once("://")
            .ok_or(DiscoveryError::InvalidEndpoint)?;
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        Ok(format!("{scheme}://{authority}/.well-known/gnap-as-rs"))
    }
}

/// Public information about an active token, never the token value (§3.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveIntrospection {
    /// Disclosable rights, possibly an empty array.
    pub access: Vec<AccessItem>,
    /// The issuing AS's exact grant endpoint; required even when access is empty.
    pub iss: String,
    /// The client's key binding; required unless the token is bearer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Key>,
    /// Flags associated with the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<AccessTokenFlag>>,
    /// Exclusive expiration timestamp in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issuance timestamp in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Additional response fields, excluding credentials and active itself.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ActiveIntrospection {
    /// Checks required key binding and prevents credentials leaking in extensions.
    ///
    /// This does not verify a key, interpret access, validate issuer trust, or
    /// decide whether the token is still live. Those are the roles' duties.
    /// # Errors
    /// Returns a field-level explanation of an invalid active response.
    pub fn validate(&self) -> Result<(), &'static str> {
        let bearer = self
            .flags
            .as_ref()
            .is_some_and(|flags| flags.contains(&AccessTokenFlag::Bearer));
        if bearer == self.key.is_some() {
            return Err("introspection.key: required for bound tokens, forbidden for bearer tokens (RFC 9767 §3.3)");
        }
        if [
            "active", "access", "iss", "key", "flags", "exp", "iat", "value", "manage", "continue",
        ]
        .iter()
        .any(|name| self.extra.contains_key(*name))
        {
            return Err("introspection: credential or reserved field in response (RFC 9767 §3.3)");
        }
        Ok(())
    }
}

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// A token introspection decision. Inactive responses cannot carry other fields.
#[derive(Debug, Clone, PartialEq)]
pub enum IntrospectionResponse {
    /// Not active in the supplied context, including an indeterminate result.
    Inactive,
    /// Information needed for the RS's own authorization decision.
    Active(ActiveIntrospection),
}

impl Serialize for IntrospectionResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Inactive => {
                let mut object = Map::new();
                object.insert("active".into(), Value::Bool(false));
                object.serialize(serializer)
            }
            Self::Active(token) => {
                token.validate().map_err(serde::ser::Error::custom)?;
                let Value::Object(mut object) =
                    serde_json::to_value(token).map_err(serde::ser::Error::custom)?
                else {
                    return Err(serde::ser::Error::custom("introspection must be an object"));
                };
                object.insert("active".into(), Value::Bool(true));
                object.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for IntrospectionResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = IntrospectionResponse;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an introspection response object (RFC 9767 §3.3)")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut object = Map::<String, Value>::new();
                while let Some((name, value)) = map.next_entry::<String, Value>()? {
                    if object.insert(name, value).is_some() {
                        return Err(de::Error::custom("duplicate introspection response field"));
                    }
                }
                match object.remove("active") {
                    Some(Value::Bool(false)) if object.is_empty() => Ok(IntrospectionResponse::Inactive),
                    Some(Value::Bool(true)) => {
                        let token: ActiveIntrospection = serde_json::from_value(Value::Object(object)).map_err(de::Error::custom)?;
                        token.validate().map_err(de::Error::custom)?;
                        Ok(IntrospectionResponse::Active(token))
                    }
                    _ => Err(de::Error::custom("introspection.active: required boolean; inactive responses carry no other fields (RFC 9767 §3.3)")),
                }
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
