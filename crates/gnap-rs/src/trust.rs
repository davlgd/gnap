use crate::AuthorizationError;
use gnap_registry::KeyProofingMethod;
use gnap_types::{message::DiscoveryError, rs::RsDiscovery};

/// Deployment-approved endpoints, never inferred from a presented token.
///
/// Exact strings identify the grant issuer and introspection destination. The
/// latter may be separately hosted: configuring it explicitly grants that
/// destination access to presented credentials. Discovery must agree with both
/// pinned endpoints; it cannot replace either or add a trusted destination.
#[derive(Debug, Clone)]
pub struct TrustedAs {
    grant: String,
    introspection: String,
    discovery: String,
    local: bool,
}
impl TrustedAs {
    /// Pins HTTPS endpoints and derives the standard RS-facing discovery URL.
    /// # Errors
    /// Rejects malformed or non-HTTPS endpoints through the shared validator,
    /// and userinfo in either authority as an additional SDK restriction.
    pub fn new(
        grant_endpoint: impl Into<String>,
        introspection_endpoint: impl Into<String>,
    ) -> Result<Self, DiscoveryError> {
        Self::build(grant_endpoint.into(), introspection_endpoint.into(), false)
    }

    /// Explicitly allows HTTP-loopback development endpoints as well as HTTPS.
    ///
    /// This is a labelled deployment deviation, not an exception in the RFC.
    /// It does not enable HTTP for other hosts or disable endpoint matching.
    /// # Errors
    /// Rejects malformed endpoints, authority userinfo and HTTP on non-loopback hosts.
    pub fn for_local_development(
        grant_endpoint: impl Into<String>,
        introspection_endpoint: impl Into<String>,
    ) -> Result<Self, DiscoveryError> {
        Self::build(grant_endpoint.into(), introspection_endpoint.into(), true)
    }

    fn build(grant: String, introspection: String, local: bool) -> Result<Self, DiscoveryError> {
        // A deployment configuration restriction, not a general RFC URL rule.
        // Keep @ in paths/queries valid; only authority userinfo is refused.
        for endpoint in [&grant, &introspection] {
            if endpoint.split_once("://").is_some_and(|(_, rest)| {
                rest.split(['/', '?'])
                    .next()
                    .is_some_and(|authority| authority.contains('@'))
            }) {
                return Err(DiscoveryError::InvalidEndpoint);
            }
        }
        let metadata = RsDiscovery {
            grant_request_endpoint: grant.clone(),
            introspection_endpoint: Some(introspection.clone()),
            token_formats_supported: None,
            resource_registration_endpoint: None,
            key_proofs_supported: None,
            extra: serde_json::Map::new(),
        };
        let discovery = discovery_url(&metadata, local)?;
        Ok(Self {
            grant,
            introspection,
            discovery,
            local,
        })
    }

    /// The exact trusted issuer and grant endpoint.
    #[must_use]
    pub fn grant_endpoint(&self) -> &str {
        &self.grant
    }
    /// The exact approved destination of signed introspection requests.
    #[must_use]
    pub fn introspection_endpoint(&self) -> &str {
        &self.introspection
    }
    /// The well-known URL derived by the shared RFC 9767 discovery validator.
    #[must_use]
    pub fn discovery_endpoint(&self) -> &str {
        &self.discovery
    }

    pub(crate) fn accepts(&self, metadata: &RsDiscovery) -> Result<(), AuthorizationError> {
        if discovery_url(metadata, self.local).as_deref() != Ok(self.discovery.as_str())
            || metadata.grant_request_endpoint != self.grant
            || metadata.introspection_endpoint.as_deref() != Some(self.introspection.as_str())
            || metadata
                .key_proofs_supported
                .as_ref()
                .is_some_and(|proofs| !proofs.contains(&KeyProofingMethod::Httpsig))
        {
            return Err(AuthorizationError::Unavailable);
        }
        Ok(())
    }
}
fn discovery_url(metadata: &RsDiscovery, local: bool) -> Result<String, DiscoveryError> {
    if local {
        metadata.discovery_url_for_local_development()
    } else {
        metadata.discovery_url()
    }
}
