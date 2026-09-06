//! Explicit token selection and atomic batch preparation. No storage writes
//! occur here: the grant handler publishes the complete aggregate once.

use super::{
    credential_used, misconfigured, ok, AccessToken, AccessTokenResponse, AuthorizationServer,
    BoundToken, Continue, GrantAggregate, GrantRequest, GrantResponse, GrantSnapshot, HttpResponse,
    KeyResolver, Nonces, Policy, PreparedToken, ReleasedSubject, Storage, SubjectGround,
    TokenEncoder, TokenManage, TokenRecord, TokenValue,
};
use crate::policy::TokenApproval;
use std::collections::{HashMap, HashSet};

// Resource bound on trusted policy output, not a GNAP array-size requirement.
const MAX_APPROVALS: usize = 64;

struct Reserved {
    candidate: TokenValue,
    handle: String,
    management: TokenValue,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Candidate(usize),
    Management,
    Continuation,
}

fn selected(
    request: &GrantRequest,
    approvals: Vec<TokenApproval>,
) -> Result<Vec<TokenApproval>, HttpResponse> {
    let Some(wanted) = &request.access_token else {
        return Err(misconfigured("token selection requires a token request"));
    };
    if approvals.is_empty() || approvals.len() > MAX_APPROVALS {
        return Err(misconfigured(
            "token selection is empty or exceeds the SDK bound",
        ));
    }
    let mut labels = HashSet::new();
    if approvals.iter().any(|approval| {
        !labels.insert(approval.requested_label.as_deref())
            || !wanted
                .tokens
                .iter()
                .any(|token| token.label == approval.requested_label)
    }) {
        return Err(misconfigured(
            "policy selected unknown or repeated token labels",
        ));
    }
    // The policy can choose any subset. Response order follows request order;
    // consumers must still correlate by label, never by position.
    let mut approvals: HashMap<_, _> = approvals
        .into_iter()
        .map(|approval| (approval.requested_label.clone(), approval))
        .collect();
    Ok(wanted
        .tokens
        .iter()
        .filter_map(|token| approvals.remove(&token.label))
        .collect())
}

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    pub(super) fn approve_selected(
        &self,
        aggregate: &mut GrantAggregate,
        approvals: Vec<TokenApproval>,
        subject: Option<ReleasedSubject>,
        now: u64,
        authenticated: Option<&GrantSnapshot>,
    ) -> HttpResponse {
        let approvals = match selected(&aggregate.record.request, approvals) {
            Ok(approvals) => approvals,
            Err(response) => return response,
        };
        if let Some(released) = &subject {
            if released.ground == SubjectGround::RoInteractedHere
                && !aggregate.record.interaction_completed
            {
                return misconfigured("subject release claims an interaction that did not occur");
            }
            if let Err(error) = released.subject.validate() {
                return misconfigured(&error.to_string());
            }
        }
        let request = &aggregate.record.request;
        let keep_open = self.policy.keep_grant_open(request);
        let (prepared, continuation) =
            match self.prepare_selected(request, &approvals, now, keep_open, authenticated) {
                Ok(prepared) => prepared,
                Err(response) => return response,
            };
        let mut records = HashMap::new();
        let mut tokens = Vec::with_capacity(prepared.len());
        for (approval, prepared) in approvals.into_iter().zip(prepared) {
            let token = AccessToken {
                value: prepared.encoded.value,
                label: approval.requested_label,
                manage: Some(TokenManage {
                    uri: format!(
                        "{}/{}",
                        self.endpoints.token_management.trim_end_matches('/'),
                        prepared.management
                    ),
                    access_token: BoundToken::new(prepared.management_token.clone()),
                }),
                access: Some(approval.access),
                expires_in: prepared.expires_in,
                key: None,
                flags: Vec::new(),
                extra: serde_json::Map::new(),
            };
            if token.validate().is_err() || aggregate.tokens.contains_key(&prepared.management) {
                return misconfigured("invalid prepared token or repeated management handle");
            }
            let record = TokenRecord {
                derivation: None,
                identifier: prepared.encoded.identifier,
                issued_at: now,
                token: token.clone(),
                client: request.client.clone(),
                management_token: prepared.management_token.as_str().into(),
            };
            if records.insert(prepared.management, record).is_some() {
                return misconfigured("repeated token management handle");
            }
            tokens.push(token);
        }
        let Some(cardinality) = request
            .access_token
            .as_ref()
            .map(|tokens| tokens.cardinality)
        else {
            return misconfigured("token selection requires a token request");
        };
        let response_tokens = AccessTokenResponse {
            cardinality,
            tokens,
        };
        if response_tokens.validate().is_err() {
            return misconfigured("invalid prepared token response");
        }
        // Only this final assignment replaces old authority in the candidate.
        // Its caller still has to commit the whole aggregate by create/CAS.
        aggregate.tokens = records;
        let mut response = GrantResponse {
            access_token: Some(response_tokens),
            ..GrantResponse::default()
        };
        complete_approval(
            &mut aggregate.record,
            &mut response,
            subject,
            continuation,
            now,
            &self.endpoints.continuation,
        );
        ok(&response)
    }

    fn prepare_selected(
        &self,
        request: &GrantRequest,
        approvals: &[TokenApproval],
        now: u64,
        keep_open: bool,
        authenticated: Option<&GrantSnapshot>,
    ) -> Result<(Vec<PreparedToken>, Option<TokenValue>), HttpResponse> {
        if approvals.len() == 1 {
            // Preserve the existing candidate/handle/credential/continuation
            // sequence, including when only the second requested slot is issued.
            let mut token = self.encode_issued_token(
                request,
                &approvals[0].access,
                now,
                keep_open,
                authenticated,
            )?;
            let continuation = token.continuation.take();
            return Ok((vec![token], continuation));
        }
        let expires_in = self.access_token_lifetime(request, now)?;
        let mut roles = HashMap::new();
        let mut handles = HashSet::new();
        let mut reserved = Vec::with_capacity(approvals.len());
        let repeated =
            |value: &str| authenticated.is_some_and(|old| credential_used(&old.aggregate, value));
        for index in 0..approvals.len() {
            let candidate = generated(self.nonces.next())?;
            let handle = self.nonces.next();
            let management = generated(self.nonces.next())?;
            if handle.is_empty()
                || !handles.insert(handle.clone())
                || authenticated.is_some_and(|old| old.aggregate.tokens.contains_key(&handle))
            {
                return Err(misconfigured(
                    "generated management handle is empty or repeated",
                ));
            }
            for (value, role) in [
                (&candidate, Role::Candidate(index)),
                (&management, Role::Management),
            ] {
                if repeated(value.as_str())
                    || roles.insert(value.as_str().to_owned(), role).is_some()
                {
                    return Err(misconfigured("generated batch credentials collide"));
                }
            }
            reserved.push(Reserved {
                candidate,
                handle,
                management,
            });
        }
        let continuation = if keep_open {
            let value = generated(self.nonces.next())?;
            if repeated(value.as_str())
                || roles
                    .insert(value.as_str().into(), Role::Continuation)
                    .is_some()
            {
                return Err(misconfigured(
                    "generated continuation collides with batch credentials",
                ));
            }
            Some(value)
        } else {
            None
        };
        let mut values = HashSet::new();
        let mut identifiers = HashSet::new();
        let mut prepared = Vec::with_capacity(approvals.len());
        // No encoder is invoked before ALL sibling credentials are known.
        for (index, (approval, reserved)) in approvals.iter().zip(reserved).enumerate() {
            let encoded = self
                .encode_access_token(
                    &request.client,
                    None,
                    &approval.access,
                    now,
                    expires_in,
                    &reserved.candidate,
                )
                .map_err(|_| misconfigured("unable to encode a token in the approved batch"))?;
            if repeated(encoded.value.as_str())
                || roles
                    .get(encoded.value.as_str())
                    .is_some_and(|role| *role != Role::Candidate(index))
                || !values.insert(encoded.value.clone())
            {
                return Err(misconfigured("encoded batch credentials collide"));
            }
            reserve_identifier(
                encoded.identifier.as_deref(),
                &mut identifiers,
                authenticated,
            )?;
            prepared.push(PreparedToken {
                encoded,
                expires_in,
                management: reserved.handle,
                management_token: reserved.management,
                continuation: None,
            });
        }
        Ok((prepared, continuation))
    }
}

fn reserve_identifier(
    identifier: Option<&[u8]>,
    identifiers: &mut HashSet<Vec<u8>>,
    authenticated: Option<&GrantSnapshot>,
) -> Result<(), HttpResponse> {
    if let Some(identifier) = identifier {
        if !identifiers.insert(identifier.to_vec())
            || authenticated.is_some_and(|old| {
                old.aggregate
                    .tokens
                    .values()
                    .any(|token| token.identifier.as_deref() == Some(identifier))
            })
        {
            return Err(misconfigured("encoded batch identifiers collide"));
        }
    }
    Ok(())
}

fn generated(value: String) -> Result<TokenValue, HttpResponse> {
    TokenValue::new(value)
        .map_err(|_| misconfigured("generated batch credential is outside token68"))
}

pub(super) fn complete_approval(
    record: &mut crate::storage::GrantRecord,
    response: &mut GrantResponse,
    subject: Option<ReleasedSubject>,
    continuation: Option<TokenValue>,
    now: u64,
    continuation_uri: &str,
) {
    response.subject = subject.map(|released| *released.subject);
    record.interact_handle = None;
    record.interact_ref = None;
    record.interact_expires_at = None;
    if let Some(continuation) = continuation {
        record.continuation_token = Some(continuation.as_str().to_owned());
        record
            .grant
            .offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
        response.r#continue = Some(Continue {
            uri: continuation_uri.to_owned(),
            access_token: BoundToken::new(continuation),
            wait: Some(gnap_core::DEFAULT_WAIT),
            extra: serde_json::Map::new(),
        });
    } else {
        record.grant.withhold_continuation();
    }
}
