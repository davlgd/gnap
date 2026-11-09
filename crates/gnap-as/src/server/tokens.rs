//! Access-token encoding and lifetimes, at issuance and at rotation.

use super::{credential_used, misconfigured, AuthorizationServer, PreparedToken};
use crate::encoding::{EncodedToken, TokenEncoder, TokenEncodingContext, TokenEncodingError};
use crate::nonce::Nonces;
use crate::policy::{KeyResolver, Policy};
use crate::storage::{GrantAggregate, GrantSnapshot, Storage, TokenRecord};
use gnap_types::access::AccessItem;
use gnap_types::client::Client;
use gnap_types::http::HttpResponse;
use gnap_types::message::GrantRequest;
use gnap_types::token::TokenValue;

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    pub(super) fn encode_rotated_token(
        &self,
        record: &TokenRecord,
        aggregate: &GrantAggregate,
        now: u64,
        candidate: &TokenValue,
        management: &TokenValue,
    ) -> Result<EncodedToken, TokenEncodingError> {
        // A broken nonce source must not expose a management credential as
        // an encoder input, even by accidentally repeating its value.
        if candidate == management
            || credential_used(aggregate, candidate.as_str())
            || credential_used(aggregate, management.as_str())
        {
            return Err(TokenEncodingError);
        }
        self.encode_access_token(
            &record.client,
            record.token.key.as_ref(),
            record.token.access.as_deref().unwrap_or_default(),
            now,
            record.token.expires_in,
            candidate,
        )
    }

    pub(super) fn encode_issued_token(
        &self,
        request: &GrantRequest,
        access: &[AccessItem],
        now: u64,
        keep_open: bool,
        authenticated: Option<&GrantSnapshot>,
    ) -> Result<PreparedToken, HttpResponse> {
        let expires_in = self.access_token_lifetime(request, now)?;
        self.encode_issued_with_lifetime(request, access, now, keep_open, authenticated, expires_in)
    }

    pub(super) fn encode_issued_with_lifetime(
        &self,
        request: &GrantRequest,
        access: &[AccessItem],
        now: u64,
        keep_open: bool,
        authenticated: Option<&GrantSnapshot>,
        expires_in: Option<u64>,
    ) -> Result<PreparedToken, HttpResponse> {
        let candidate = TokenValue::new(self.nonce()?).map_err(|_| {
            misconfigured("Nonces returned an access value outside token68 (RFC 9635 §3.2.1)")
        })?;
        // Preserve the nominal candidate → handle → credential order, but
        // reserve all three before encoding. A repeating source must not pass
        // the management credential to the encoder as its candidate.
        let management = self.nonce()?;
        let management_token = TokenValue::new(self.nonce()?).map_err(|_| {
            misconfigured("Nonces returned a management value outside token68 (RFC 9635 §3.2.1)")
        })?;
        let continuation = if keep_open {
            Some(
                TokenValue::new(self.nonce()?)
                    .map_err(|_| misconfigured("Nonces returned an invalid continuation value"))?,
            )
        } else {
            None
        };
        let repeated = |value: &str| {
            authenticated.is_some_and(|snapshot| credential_used(&snapshot.aggregate, value))
        };
        if candidate == management_token
            || continuation.as_ref().is_some_and(|value| {
                value == &candidate || value == &management_token || repeated(value.as_str())
            })
            || repeated(candidate.as_str())
            || repeated(management_token.as_str())
        {
            return Err(misconfigured(
                "generated values repeat access, management or continuation credentials",
            ));
        }
        let encoded = self
            .encode_access_token(&request.client, None, access, now, expires_in, &candidate)
            .map_err(|_| misconfigured("unable to encode an access token"))?;
        if encoded.value == management_token
            || continuation.as_ref() == Some(&encoded.value)
            || repeated(encoded.value.as_str())
        {
            return Err(misconfigured(
                "encoded access value repeats another credential",
            ));
        }
        if encoded.identifier.as_ref().is_some_and(|identifier| {
            authenticated.is_some_and(|snapshot| {
                snapshot
                    .aggregate
                    .tokens
                    .values()
                    .any(|token| token.identifier.as_ref() == Some(identifier))
            })
        }) {
            return Err(misconfigured(
                "encoded token repeats a previous format identifier",
            ));
        }
        Ok(PreparedToken {
            encoded,
            expires_in,
            management,
            management_token,
            continuation,
        })
    }

    pub(super) fn encode_access_token(
        &self,
        client: &Client,
        binding: Option<&gnap_types::key::Key>,
        access: &[AccessItem],
        issued_at: u64,
        expires_in: Option<u64>,
        candidate: &TokenValue,
    ) -> Result<EncodedToken, TokenEncodingError> {
        let encoded = self.encoder.encode(&TokenEncodingContext {
            issuer: &self.endpoints.grant,
            client,
            binding,
            access,
            issued_at,
            expires_in,
            candidate_nonce: candidate.as_str(),
        })?;
        if encoded.identifier.as_ref().is_some_and(Vec::is_empty) {
            return Err(TokenEncodingError);
        }
        Ok(encoded)
    }

    pub(super) fn access_token_lifetime(
        &self,
        request: &GrantRequest,
        now: u64,
    ) -> Result<Option<u64>, HttpResponse> {
        let seconds = self
            .policy
            .token_lifetime(request)
            .map(std::num::NonZeroU64::get);
        if seconds.is_some_and(|seconds| now.checked_add(seconds).is_none()) {
            Err(misconfigured(
                "token lifetime exceeds the representable expiration time",
            ))
        } else {
            Ok(seconds)
        }
    }
}
