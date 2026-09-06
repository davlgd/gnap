use crate::AuthorizationError;
use gnap_types::{access::AccessItem, rs::ActiveIntrospection};
use serde_json::Value;

/// How this deployment establishes the introspected token's audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudiencePolicy {
    /// Trust the AS's active decision for this authenticated RS and requested
    /// rights. Accepts omitted `aud` only, never ignores a supplied audience.
    IntrospectionContext,
    /// Require `aud` to contain this exact configured audience string. This is
    /// not automatically the RS's registration reference or its HTTP origin.
    Exact(String),
}
impl AudiencePolicy {
    pub(crate) fn check(&self, audience: Option<&Audience<'_>>) -> Result<(), AuthorizationError> {
        match (self, audience) {
            (Self::IntrospectionContext, None) => Ok(()),
            (Self::IntrospectionContext, Some(_)) => Err(AuthorizationError::Unavailable),
            (Self::Exact(expected), Some(audience)) if audience.contains(expected) => Ok(()),
            (Self::Exact(_), _) => Err(AuthorizationError::Denied),
        }
    }
}

/// A strictly decoded `aud` field; empty arrays contain no accepted audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience<'a> {
    /// One audience string.
    Single(&'a str),
    /// An array consisting only of audience strings.
    Multiple(Vec<&'a str>),
}
impl Audience<'_> {
    /// Exact membership without URI normalization or inferred aliases.
    #[must_use]
    pub fn contains(&self, audience: &str) -> bool {
        match self {
            Self::Single(value) => *value == audience,
            Self::Multiple(values) => values.contains(&audience),
        }
    }
}

/// Read-only policy input, excluding token values, keys and raw responses.
///
/// The AS must be trusted to assert this information. Rights still require
/// application interpretation; the SDK only checks exact required membership.
pub struct TokenInfo<'a> {
    /// Rights disclosed by introspection, not automatically resource permission.
    pub access: &'a [AccessItem],
    /// Mandatory issuance time, in Unix seconds.
    pub issued_at: u64,
    /// Mandatory exclusive expiration time, in Unix seconds.
    pub expires_at: u64,
    /// Optional inclusive validity start, in Unix seconds.
    pub not_before: Option<u64>,
    /// Optional explicitly asserted audience.
    pub audience: Option<Audience<'a>>,
    /// Optional AS-local subject identifier, not a globally unique identity.
    pub subject: Option<&'a str>,
    /// Optional AS-local client-instance identifier, not its cryptographic key.
    pub instance_id: Option<&'a str>,
}
impl<'a> TokenInfo<'a> {
    pub(crate) fn from_active(active: &'a ActiveIntrospection) -> Result<Self, AuthorizationError> {
        let (Some(issued_at), Some(expires_at)) = (active.iat, active.exp) else {
            return Err(AuthorizationError::Unavailable);
        };
        if expires_at <= issued_at
            || active
                .extra
                .keys()
                .any(|key| !["aud", "nbf", "sub", "instance_id"].contains(&key.as_str()))
        {
            return Err(AuthorizationError::Unavailable);
        }
        let audience = match active.extra.get("aud") {
            None => None,
            Some(Value::String(value)) => Some(Audience::Single(value)),
            Some(Value::Array(values)) => Some(Audience::Multiple(
                values
                    .iter()
                    .map(|value| value.as_str().ok_or(AuthorizationError::Unavailable))
                    .collect::<Result<_, _>>()?,
            )),
            Some(_) => return Err(AuthorizationError::Unavailable),
        };
        let not_before = active
            .extra
            .get("nbf")
            .map(|value| value.as_u64().ok_or(AuthorizationError::Unavailable))
            .transpose()?;
        let subject = optional_string(active, "sub")?;
        let instance_id = optional_string(active, "instance_id")?;
        Ok(Self {
            access: &active.access,
            issued_at,
            expires_at,
            not_before,
            audience,
            subject,
            instance_id,
        })
    }

    pub(crate) fn check_time(&self, previous: u64, now: u64) -> Result<(), AuthorizationError> {
        if now < previous
            || now < self.issued_at
            || now >= self.expires_at
            || self.not_before.is_some_and(|start| now < start)
        {
            return Err(AuthorizationError::Denied);
        }
        Ok(())
    }
}
fn optional_string<'a>(
    active: &'a ActiveIntrospection,
    field: &str,
) -> Result<Option<&'a str>, AuthorizationError> {
    active
        .extra
        .get(field)
        .map(|value| value.as_str().ok_or(AuthorizationError::Unavailable))
        .transpose()
}

/// Application semantics that can only further restrict a valid token request.
///
/// This callback runs before the client's proof is verified. It must not perform
/// the protected operation or treat invocation as authenticated client activity.
pub trait AccessPolicy {
    /// Approves the disclosed rights/subject for the application operation.
    /// Returning `Ok` never bypasses issuer, audience, time, proof or replay checks.
    /// # Errors
    /// Returns `Denied` for refused access or `Unavailable` for information the
    /// application's profile cannot use. Either result prevents authorization.
    fn validate(&self, token: &TokenInfo<'_>) -> Result<(), AuthorizationError>;
}
impl<F: Fn(&TokenInfo<'_>) -> Result<(), AuthorizationError>> AccessPolicy for F {
    fn validate(&self, token: &TokenInfo<'_>) -> Result<(), AuthorizationError> {
        self(token)
    }
}
