//! One fictional resource owner and one application client, never a login system.
use super::*;
use gnap_as::{ReleasedSubject, SubjectGround};
use gnap_subject::{Issuance, Trust};

const LIFETIME: u64 = 300;

pub(super) struct Identity {
    issuer: String,
    endpoint: String,
    audience: String,
    subject: String,
    signer: Ps256Signer,
    verifier: gnap_crypto::Ps256Verifier,
}

impl Identity {
    pub fn generate(origin: &str, client: &Ps256Signer) -> Result<Option<Arc<Self>>, &'static str> {
        if !origin.starts_with("https://") {
            return Ok(None);
        }
        let signer = Ps256Signer::generate(2048, "delegation-demo-subject")
            .map_err(|_| "Subject signing key unavailable")?;
        let verifier = signer.verifier();
        Ok(Some(Arc::new(Self {
            issuer: origin.into(),
            endpoint: format!("{origin}/gnap"),
            audience: client.thumbprint(),
            // This deployment has exactly one fictional RO and one client key.
            // Do not present this as a general pairwise account identifier store.
            subject: fresh_nonce().map_err(|_| "Subject randomness unavailable")?,
            signer,
            verifier,
        })))
    }

    fn trust(&self) -> Trust<'_> {
        Trust {
            as_endpoint: &self.endpoint,
            issuer: &self.issuer,
            key: &self.verifier,
            max_age: LIFETIME,
            clock_skew: 0,
        }
    }
}

pub(super) fn request() -> Value {
    json!({"sub_id_formats":["opaque", "iss_sub"], "assertion_formats":["id_token"]})
}

pub(super) fn acceptable_request(request: &GrantRequest, identity: Option<&Identity>) -> bool {
    let Some(subject) = &request.subject else {
        return true;
    };
    identity.is_some()
        && serde_json::to_value(subject).ok() == Some(self::request())
        && request
            .access_token
            .as_ref()
            .is_some_and(|tokens| tokens.cardinality == gnap_types::token::Cardinality::Single)
        && request
            .interact
            .as_ref()
            .and_then(|i| i.finish.as_ref())
            .is_some_and(|finish| finish.method == gnap_registry::InteractionFinishMethod::Redirect)
}

pub(super) fn release(
    decision: Decision,
    request: &GrantRequest,
    decided_at: u64,
    identity: Option<&Identity>,
) -> Decision {
    if request.subject.is_none() {
        return decision;
    }
    let Decision::Approve { access, .. } = decision else {
        return decision;
    };
    let denied = || Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
    let Some(identity) = identity else {
        return denied();
    };
    let Some(finish) = request.interact.as_ref().and_then(|i| i.finish.as_ref()) else {
        return denied();
    };
    let issued_at = now();
    let Ok(assertion) = gnap_subject::issue(
        &identity.signer,
        &Issuance {
            issuer: &identity.issuer,
            subject: &identity.subject,
            audience: &identity.audience,
            nonce: &finish.nonce,
            // A fictional authentication event: explicit sandbox consent, not proof
            // that a real person authenticated. The UI and README make this explicit.
            authenticated_at: decided_at,
            issued_at,
            expires_at: issued_at.saturating_add(LIFETIME),
        },
    ) else {
        return denied();
    };
    let subject = serde_json::from_value(json!({
        "sub_ids":[{"format":"opaque", "id":identity.subject},
            {"format":"iss_sub", "iss":identity.issuer, "sub":identity.subject}],
        "assertions":[assertion]
    }))
    .expect("fixed subject response shape");
    Decision::Approve {
        access,
        subject: Some(ReleasedSubject {
            ground: SubjectGround::RoInteractedHere,
            subject: Box::new(subject),
        }),
    }
}

pub(super) fn view(session: &BrowserSession<'_>, at: u64) -> Value {
    let Some(identity) = &session.identity else {
        return Value::Null;
    };
    verified_view(&session.client, identity, at)
}

fn verified_view<T: HttpTransport>(
    client: &Session<'_, T, Ps256Signer>,
    identity: &Identity,
    at: u64,
) -> Value {
    match client.verify_subject(&identity.trust(), at) {
        Ok(verified) => json!({
            "status":"verified", "as_endpoint":verified.as_endpoint,
            "issuer":verified.identity.issuer(), "subject":verified.identity.subject(),
            "expires_at":verified.identity.expires_at(),
        }),
        Err(_) => json!({"status":"unavailable"}),
    }
}

#[cfg(test)]
mod tests;
