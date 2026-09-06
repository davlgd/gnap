//! The new binding reaches encoders and RS introspection, not the grant identity.

use super::*;
use gnap_as::{
    EncodedToken, IntrospectionDecision, IntrospectionPolicy, ResolvedResourceServer,
    ResourceServerResolver, RsId, TokenEncoder, TokenEncodingContext, TokenEncodingError,
};
use gnap_types::{access::AccessItem, rs::ResourceServer, token::TokenValue};
use std::cell::RefCell;

struct RecordingEncoder<'a> {
    calls: &'a RefCell<Vec<(Client, Option<Key>)>>,
    refuse_binding: bool,
}

impl TokenEncoder for RecordingEncoder<'_> {
    fn encode(
        &self,
        context: &TokenEncodingContext<'_>,
    ) -> Result<EncodedToken, TokenEncodingError> {
        self.calls
            .borrow_mut()
            .push((context.client.clone(), context.binding.cloned()));
        if self.refuse_binding && context.binding.is_some() {
            return Err(TokenEncodingError);
        }
        Ok(EncodedToken {
            value: TokenValue::new(context.candidate_nonce).map_err(|_| TokenEncodingError)?,
            identifier: None,
        })
    }
}

#[test]
fn an_encoder_receives_the_explicit_binding_and_can_refuse_it_without_publication() {
    for refuse_binding in [false, true] {
        let calls = RefCell::new(Vec::new());
        let server = server(true, true).with_token_encoder(RecordingEncoder {
            calls: &calls,
            refuse_binding,
        });
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let original_client = before.aggregate.record.request.client.clone();
        assert_eq!(calls.borrow().len(), 2);
        assert!(calls
            .borrow()
            .iter()
            .all(|(client, binding)| { client == &original_client && binding.is_none() }));
        calls.borrow_mut().clear();
        let request = rotate_request(&tokens[0], &presented(new_key()), None);
        let response = server.handle(&request, NOW + 1);
        let expected = Some(Key::ByValue(Box::new(presented(new_key()))));
        assert_eq!(
            calls.borrow().as_slice(),
            &[(original_client.clone(), expected.clone())]
        );
        if refuse_binding {
            assert_eq!(error_code(&response), "invalid_rotation");
            unchanged(&server, &tokens[0], &before);
        } else {
            let rotated = single(&response);
            assert_eq!(rotated.key, expected);
            let manage = rotated.manage.as_ref().unwrap();
            let refresh = sign_request(
                HttpRequest::new("POST", &manage.uri),
                new_key(),
                Some(&manage.access_token.value),
                NOW + 2,
            )
            .unwrap();
            let refreshed = single(&server.handle(&refresh, NOW + 2));
            assert_eq!(refreshed.key, expected);
            assert_eq!(calls.borrow().len(), 2);
            assert_eq!(calls.borrow()[1], (original_client, expected));
        }
    }
}

struct RegisteredRs(KeyObject);
impl ResourceServerResolver for RegisteredRs {
    fn resolve(&self, rs: &ResourceServer) -> Option<ResolvedResourceServer> {
        (rs.as_reference() == Some("files")).then(|| ResolvedResourceServer {
            id: RsId("files".into()),
            key: self.0.clone(),
        })
    }
}

struct DisclosedKey(KeyObject);
impl IntrospectionPolicy for DisclosedKey {
    fn evaluate(
        &self,
        _: &ResourceServer,
        token: &TokenRecord,
        _: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
        IntrospectionDecision::Active {
            access: token.token.access.clone().unwrap_or_default(),
            key: Some(self.0.clone()),
        }
    }
}

#[test]
fn introspection_refuses_the_original_key_after_a_real_rotation() {
    let server = server(true, true);
    let tokens = grant(&server);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    let rotated = single(&server.handle(&request, NOW + 1));
    let rs = Ps256Signer::generate(2048, "resource-server").unwrap();
    let registry = RegisteredRs(presented(&rs));
    let nonces = MemoryStorage::new();
    let endpoint = "https://as.example/introspect";
    for (disclosed, expected_active) in [(old_key(), false), (new_key(), true)] {
        let policy = DisclosedKey(presented(disclosed));
        let api = server
            .resource_server_api(&registry, &policy, &nonces, endpoint)
            .unwrap();
        let query = sign_request(
            HttpRequest::new("POST", endpoint).json_body(
                serde_json::to_vec(&json!({
                    "resource_server":"files",
                    "access_token":rotated.value,
                    "proof":"httpsig"
                }))
                .unwrap(),
            ),
            &rs,
            None,
            NOW + 2,
        )
        .unwrap();
        let response = api.handle(&query, NOW + 2);
        assert_eq!(response.status, 200);
        assert!(response.has_no_store());
        let wire: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(wire["active"], expected_active);
        if expected_active {
            assert_eq!(
                wire["key"],
                serde_json::to_value(presented(new_key())).unwrap()
            );
            assert_eq!(
                wire["access"],
                serde_json::to_value(&rotated.access).unwrap()
            );
        } else {
            assert_eq!(wire, json!({"active":false}));
        }
    }
}
