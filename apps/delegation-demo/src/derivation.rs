//! A single-purpose RS1→AS→RS2 consumer. No resource role reads AS storage.
use super::*;
use gnap_as::{DerivationPolicy, DerivedAccess, ResolvedResourceServer, RsId, TokenRecord};
use gnap_types::token::{AccessToken, AccessTokenRequest, Cardinality, TokenRequest};

pub(super) const METADATA_READ: &str = "archive-metadata:read";
pub(super) const RS1_PATH: &str = "/resource/folder-metadata";
pub(super) const RS2_PATH: &str = "/resource/archive-metadata";

/// Authentication registries are role-specific: being an introspecting RS does
/// not also enroll RS2 as a downstream grant client. Rights remain policy work.
pub(super) struct Requesters<'a>(pub &'a introspection::Registration);
impl gnap_as::ResourceServerResolver for Requesters<'_> {
    fn resolve(&self, rs: &gnap_types::rs::ResourceServer) -> Option<ResolvedResourceServer> {
        if rs.as_reference() != Some(introspection::RS_ID) {
            return None;
        }
        gnap_as::ResourceServerResolver::resolve(self.0, rs)
    }
}

impl DerivationPolicy for introspection::Registration {
    fn evaluate(
        &self,
        request: &GrantRequest,
        rs: &ResolvedResourceServer,
        _parent: &GrantSnapshot,
        token: &TokenRecord,
    ) -> Option<DerivedAccess> {
        let wanted = vec![AccessItem::Reference(METADATA_READ.into())];
        let requested = request.access_token.as_ref()?;
        if rs.id != RsId(resource_registration::RS_OWNER.into())
            || rs.key != self.key
            || token.derivation.is_some()
            || requested.cardinality != Cardinality::Single
            || requested.tokens.len() != 1
            || requested.tokens[0].access != wanted
            || !matches!(
                gnap_as::IntrospectionPolicy::evaluate(
                    self,
                    &gnap_types::rs::ResourceServer::ByReference(introspection::RS_ID.into()),
                    token,
                    Some(&[AccessItem::Reference(FOLDER_READ.into())]),
                ),
                gnap_as::IntrospectionDecision::Active { .. }
            )
        {
            return None;
        }
        Some(DerivedAccess {
            access: wanted,
            audience: RsId(introspection::RS2_OWNER.into()),
        })
    }
}

pub(super) fn management_destination(origin: &str, url: &str) -> bool {
    url.strip_prefix(&format!("{origin}/token/"))
        .is_some_and(|handle| {
            !handle.is_empty()
                && handle.len() <= 256
                && handle
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn parent_value(request: &HttpRequest) -> Result<TokenValue, ResourceError> {
    // Called only after authorize() accepted this exact request and its proof.
    let value = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, value)| value.split_once(' '))
        .map(|(_, value)| value.trim_start_matches(' '))
        .ok_or(ResourceError::Denied)?;
    TokenValue::new(value).map_err(|_| ResourceError::Denied)
}

pub(super) fn issue(
    client: &introspection::ResourceClient,
    parent: &TokenValue,
    time: u64,
) -> Result<AccessToken, ResourceError> {
    let body = GrantRequest {
        client: Client::ByReference(introspection::RS_ID.into()),
        existing_access_token: Some(parent.clone()),
        access_token: Some(AccessTokenRequest {
            cardinality: Cardinality::Single,
            tokens: vec![TokenRequest {
                access: vec![AccessItem::Reference(METADATA_READ.into())],
                label: None,
                flags: vec![],
                extra: Default::default(),
            }],
        }),
        interact: None,
        user: None,
        subject: None,
        extra: Default::default(),
    };
    let mut request = HttpRequest::new("POST", format!("{}/gnap", client.origin));
    request
        .headers
        .push(("content-type".into(), "application/json".into()));
    request.body = Some(serde_json::to_vec(&body).map_err(|_| ResourceError::Unavailable)?);
    let request = sign_request(request, client.signer.as_ref(), None, time)
        .map_err(|_| ResourceError::Unavailable)?;
    let response = client
        .transport
        .send(request)
        .map_err(|_| ResourceError::Unavailable)?;
    if !matches!(response.status, 200 | 400) {
        return Err(ResourceError::Unavailable);
    }
    let status = response.status;
    let response: gnap_types::message::GrantResponse = introspection::json_body(&response)?;
    if response.error.is_some()
        && response.access_token.is_none()
        && response.r#continue.is_none()
        && response.interact.is_none()
        && response.subject.is_none()
        && response.instance_id.is_none()
        && response.extra.is_empty()
    {
        return Err(ResourceError::Denied);
    }
    if status != 200
        || response.error.is_some()
        || response.r#continue.is_some()
        || response.interact.is_some()
        || response.subject.is_some()
        || response.instance_id.is_some()
        || !response.extra.is_empty()
    {
        return Err(ResourceError::Unavailable);
    }
    let tokens = response.access_token.ok_or(ResourceError::Unavailable)?;
    if tokens.cardinality != Cardinality::Single || tokens.tokens.len() != 1 {
        return Err(ResourceError::Unavailable);
    }
    let token = tokens
        .tokens
        .into_iter()
        .next()
        .ok_or(ResourceError::Unavailable)?;
    let expected_key = introspection::public_key(client.signer.as_ref());
    if token.validate().is_err()
        || token.label.is_some()
        || token.access.as_deref() != Some(&[AccessItem::Reference(METADATA_READ.into())])
        || !token
            .expires_in
            .is_some_and(|seconds| (1..=60).contains(&seconds))
        || !token.flags.is_empty()
        || !token.extra.is_empty()
        || token
            .key
            .as_ref()
            .is_some_and(|key| key.as_value() != Some(&expected_key))
        || token
            .manage
            .as_ref()
            .is_none_or(|manage| !management_destination(&client.origin, &manage.uri))
    {
        return Err(ResourceError::Unavailable);
    }
    Ok(token)
}

pub(super) fn revoke(
    client: &introspection::ResourceClient,
    token: &AccessToken,
    time: u64,
) -> Result<(), ResourceError> {
    let manage = token.manage.as_ref().ok_or(ResourceError::Unavailable)?;
    if !management_destination(&client.origin, &manage.uri) {
        return Err(ResourceError::Unavailable);
    }
    let request = sign_request(
        HttpRequest::new("DELETE", &manage.uri),
        client.signer.as_ref(),
        Some(&manage.access_token.value),
        time,
    )
    .map_err(|_| ResourceError::Unavailable)?;
    let response = client
        .transport
        .send(request)
        .map_err(|_| ResourceError::Unavailable)?;
    if response.status == 204 && response.body.is_empty() {
        Ok(())
    } else {
        Err(ResourceError::Unavailable)
    }
}

pub(super) fn read(
    client: &introspection::ResourceClient,
    request: &HttpRequest,
    clock: impl Fn() -> u64,
) -> Result<Value, ResourceError> {
    let started = Instant::now();
    client.authorize(request, FOLDER_READ, &clock)?;
    let child = issue(client, &parent_value(request)?, clock())?;
    let result = (|| {
        let request = sign_request(
            HttpRequest::new("GET", format!("{}{}", client.origin, RS2_PATH)),
            client.signer.as_ref(),
            Some(&child.value),
            clock(),
        )
        .map_err(|_| ResourceError::Unavailable)?;
        let response = client
            .transport
            .send(request)
            .map_err(|_| ResourceError::Unavailable)?;
        if response.status == 401 {
            return Err(ResourceError::Denied);
        }
        let metadata: Metadata = introspection::json_response(response)?;
        if metadata.source != "synthetic-archive" || metadata.document_count != 1 {
            return Err(ResourceError::Unavailable);
        }
        Ok(
            json!({"folder":"synthetic-project-orion","metadata":metadata,"granted_right":FOLDER_READ,"derived_right":METADATA_READ,"derived_lifetime_seconds":child.expires_in,"decision_source":"RS1 derived a separate key-bound token; RS2 checked authenticated introspection and the RS1 proof"}),
        )
    })();
    // One attempt even when RS2 refuses or is unavailable; never retry a grant
    // or conceal failed cleanup. Finite expiry and parent cascade remain bounds.
    let cleanup = revoke(client, &child, clock());
    // This checks completed-work latency, not cancellation of blocking calls.
    if started.elapsed() > Duration::from_secs(12) {
        return Err(ResourceError::Unavailable);
    }
    cleanup?;
    result
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub source: String,
    pub document_count: u64,
}
