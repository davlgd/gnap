//! Real root chains and GNAP HTTP message signatures, including hostile inputs.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PublicKey};
use gnap_biscuit::{
    inspect, Error, FileAction, FileRight, Issuer, RequestContext, RevocationStatus, VerifiedToken,
};
use gnap_crypto::{
    httpsig::{sign, Component, Message, SignatureInput, Tag},
    Ps256Signer, SignedRequest, Signer,
};
use gnap_types::{access::AccessItem, token::TokenValue};
use prost::Message as _;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
};

const ISSUER: &str = "https://as.example/tx";
const AUDIENCE: &str = "https://rs.example";
const ONE: &str = "https://rs.example/files/one";
const TWO: &str = "https://rs.example/files/two";
// Public RFC 9421 Appendix B.1.2 test key, never a deployment credential.
const PRIVATE: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");

struct Fixture {
    signer: Ps256Signer,
    roots: BTreeMap<u32, PublicKey>,
    token: VerifiedToken,
}

impl Fixture {
    fn new() -> Self {
        let signer = Ps256Signer::from_pkcs1_pem(PRIVATE, "client").unwrap();
        let root = KeyPair::new();
        let roots = BTreeMap::from([(7, root.public())]);
        let issuer = Issuer::new(root, 7, ISSUER.into(), AUDIENCE.into()).unwrap();
        let rights = [
            FileRight::new(ONE.into(), FileAction::Read).unwrap(),
            FileRight::new(TWO.into(), FileAction::Write).unwrap(),
        ];
        let value = issuer
            .mint(&rights, &signer.public_jwk().unwrap(), 1000, 1100)
            .unwrap();
        let token = VerifiedToken::from_token(&value, &roots).unwrap();
        Self {
            signer,
            roots,
            token,
        }
    }

    fn descendant(&self, resource: Option<&str>, deadline: Option<u64>) -> VerifiedToken {
        VerifiedToken::from_token(
            &self.token.attenuate(resource, deadline).unwrap(),
            &self.roots,
        )
        .unwrap()
    }
}

const fn context() -> RequestContext<'static> {
    RequestContext {
        issuer: ISSUER,
        audience: AUDIENCE,
        max_clock_skew: 10,
    }
}

fn headers(
    signer: &Ps256Signer,
    value: &TokenValue,
    method: &str,
    uri: &str,
    now: u64,
    nonce: Option<&str>,
) -> Vec<(String, String)> {
    let authorization = format!("GNAP {}", value.as_str());
    let message = Message {
        method,
        target_uri: uri,
        content_digest: None,
        authorization: Some(&authorization),
        other: vec![],
    };
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        created: now,
        keyid: signer.key_id().into(),
        nonce: nonce.map(Into::into),
        tag: Tag::Gnap,
    };
    let (input, signature) = sign(&message, &input, signer, "proof").unwrap();
    vec![
        ("Authorization".into(), authorization),
        ("Signature-Input".into(), input),
        ("Signature".into(), signature),
    ]
}

const fn request<'a>(
    headers: &'a [(String, String)],
    method: &'a str,
    uri: &'a str,
) -> SignedRequest<'a> {
    SignedRequest {
        method,
        target_uri: uri,
        headers,
        body: None,
    }
}

fn authorize(
    token: &VerifiedToken,
    headers: &[(String, String)],
    method: &str,
    uri: &str,
    now: u64,
) -> Result<(), Error> {
    token.authorize(
        &request(headers, method, uri),
        &context(),
        &|_: &str, _: u64| true,
        &mut || Some(now),
        &mut |_| RevocationStatus::Active,
    )
}

#[test]
fn mint_attenuate_sign_authorize_then_revoke_parent() {
    let f = Fixture::new();
    let child = f.descendant(Some(ONE), Some(1050));
    assert_eq!(inspect(child.value()).unwrap().blocks, 2);
    assert_eq!(
        child.revocation_identifiers()[0],
        f.token.revocation_identifiers()[0]
    );
    let seen = RefCell::new(HashSet::new());
    let nonces = |nonce: &str, _: u64| seen.borrow_mut().insert(nonce.to_owned());
    let revoked = RefCell::new(HashSet::<Vec<u8>>::new());
    let lookups = RefCell::new(0);
    let mut live = |ids: &[Vec<u8>]| {
        *lookups.borrow_mut() += 1;
        if ids.iter().any(|id| revoked.borrow().contains(id)) {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Active
        }
    };
    let h = headers(&f.signer, child.value(), "GET", ONE, 1010, Some("first"));
    assert_eq!(
        child.authorize(
            &request(&h, "GET", ONE),
            &context(),
            &nonces,
            &mut || Some(1010),
            &mut live
        ),
        Ok(())
    );
    assert_eq!(
        child.authorize(
            &request(&h, "GET", ONE),
            &context(),
            &nonces,
            &mut || Some(1010),
            &mut live
        ),
        Err(Error::Denied)
    );
    revoked
        .borrow_mut()
        .insert(f.token.revocation_identifiers()[0].clone());
    let h = headers(&f.signer, child.value(), "GET", ONE, 1010, Some("second"));
    assert_eq!(
        child.authorize(
            &request(&h, "GET", ONE),
            &context(),
            &nonces,
            &mut || Some(1010),
            &mut live
        ),
        Err(Error::Revoked)
    );
    assert_eq!(
        *lookups.borrow(),
        2,
        "no positive revocation cache; replay never reaches callback"
    );
}

#[test]
fn rights_remain_correlated_and_resource_checks_only_narrow() {
    let f = Fixture::new();
    for (method, uri, allowed) in [
        ("GET", ONE, true),
        ("PUT", TWO, true),
        ("PUT", ONE, false),
        ("GET", TWO, false),
        ("HEAD", ONE, false),
        ("get", ONE, false),
        ("GET", "https://rs.example/files/%6fne", false),
    ] {
        let h = headers(&f.signer, f.token.value(), method, uri, 1010, Some("nonce"));
        assert_eq!(authorize(&f.token, &h, method, uri, 1010).is_ok(), allowed);
    }
    let child = f.descendant(Some(ONE), None);
    let h = headers(&f.signer, child.value(), "PUT", TWO, 1010, Some("nonce"));
    assert_eq!(authorize(&child, &h, "PUT", TWO, 1010), Err(Error::Denied));
}

#[test]
fn wrong_key_same_kid_and_wrong_presented_token_fail() {
    let f = Fixture::new();
    let impostor = Ps256Signer::generate(2048, "client").unwrap();
    let h = headers(&impostor, f.token.value(), "GET", ONE, 1010, Some("nonce"));
    assert_eq!(
        authorize(&f.token, &h, "GET", ONE, 1010),
        Err(Error::Denied)
    );
    let child = f.descendant(Some(ONE), None);
    let h = headers(&f.signer, f.token.value(), "GET", ONE, 1010, Some("nonce"));
    assert_eq!(authorize(&child, &h, "GET", ONE, 1010), Err(Error::Denied));
    let mut h = headers(&f.signer, child.value(), "GET", ONE, 1010, Some("nonce"));
    h[0].1 = format!("GNAP {}", f.token.value().as_str());
    assert_eq!(
        authorize(&f.token, &h, "GET", ONE, 1010),
        Err(Error::Denied),
        "signature covers the descendant value"
    );
}

#[test]
fn ambiguous_headers_missing_nonce_tampered_request_and_missing_state_fail() {
    let f = Fixture::new();
    let mut h = headers(&f.signer, f.token.value(), "GET", ONE, 1010, Some("nonce"));
    h.push(("authorization".into(), h[0].1.clone()));
    assert_eq!(
        authorize(&f.token, &h, "GET", ONE, 1010),
        Err(Error::Denied)
    );
    let h = headers(&f.signer, f.token.value(), "GET", ONE, 1010, None);
    assert_eq!(
        authorize(&f.token, &h, "GET", ONE, 1010),
        Err(Error::Denied)
    );
    let h = headers(&f.signer, f.token.value(), "GET", ONE, 1010, Some("nonce"));
    assert_eq!(
        authorize(&f.token, &h, "PUT", TWO, 1010),
        Err(Error::Denied)
    );
    let r = request(&h, "GET", ONE);
    assert_eq!(
        f.token.authorize(
            &r,
            &context(),
            &|_: &str, _: u64| false,
            &mut || Some(1010),
            &mut |_| panic!("nonce failure")
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.token.authorize(
            &r,
            &context(),
            &|_: &str, _: u64| true,
            &mut || None,
            &mut |_| panic!("clock failure")
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.token.authorize(
            &r,
            &context(),
            &|_: &str, _: u64| true,
            &mut || Some(1010),
            &mut |_| RevocationStatus::Unavailable
        ),
        Err(Error::Unavailable)
    );
}

#[test]
fn issuer_audience_and_time_are_checked_independently() {
    let f = Fixture::new();
    for now in [999, 1100, u64::MAX] {
        let h = headers(&f.signer, f.token.value(), "GET", ONE, now, Some("nonce"));
        assert_eq!(authorize(&f.token, &h, "GET", ONE, now), Err(Error::Denied));
    }
    let h = headers(&f.signer, f.token.value(), "GET", ONE, 1010, Some("nonce"));
    for context in [
        RequestContext {
            issuer: "https://other.example/tx",
            ..context()
        },
        RequestContext {
            audience: "https://other.example",
            ..context()
        },
    ] {
        assert_eq!(
            f.token.authorize(
                &request(&h, "GET", ONE),
                &context,
                &|_: &str, _: u64| true,
                &mut || Some(1010),
                &mut |_| panic!("context mismatch")
            ),
            Err(Error::Denied)
        );
    }
    let child = f.descendant(None, Some(1020));
    let h = headers(&f.signer, child.value(), "GET", ONE, 1010, Some("nonce"));
    for final_time in [1009, 1020, 1100] {
        let mut times = [1010, final_time].into_iter();
        assert_eq!(
            child.authorize(
                &request(&h, "GET", ONE),
                &context(),
                &|_: &str, _: u64| true,
                &mut || times.next(),
                &mut |_| RevocationStatus::Active
            ),
            Err(Error::Denied)
        );
    }
}

fn raw(value: &TokenValue, root: PublicKey) -> Biscuit {
    Biscuit::from_base64(value.as_str(), root).unwrap()
}

fn encoded(token: &Biscuit) -> TokenValue {
    TokenValue::new(token.to_base64().unwrap()).unwrap()
}

#[test]
fn added_facts_rules_trust_and_arbitrary_expressions_are_rejected_before_evaluation() {
    let f = Fixture::new();
    let token = raw(f.token.value(), f.roots[&7]);
    let attacks = [
        BlockBuilder::new()
            .fact(r#"right("https://rs.example/admin", "write")"#)
            .unwrap(),
        BlockBuilder::new()
            .fact(r#"gnap_jwk("attacker with same kid")"#)
            .unwrap(),
        BlockBuilder::new().fact("gnap_exp(9999999)").unwrap(),
        BlockBuilder::new()
            .fact(r#"resource("https://rs.example/files/one")"#)
            .unwrap(),
        BlockBuilder::new()
            .rule("right($r, $o) <- resource($r), operation($o)")
            .unwrap(),
        BlockBuilder::new()
            .check(r#"check if resource("https://rs.example/files/one") trusting previous"#)
            .unwrap(),
        BlockBuilder::new()
            .check(r#"check if "hello".matches(".*")"#)
            .unwrap(),
        BlockBuilder::new()
            .check("check if time($t), $t + 1 < 2000")
            .unwrap(),
        BlockBuilder::new().check("check if true or true").unwrap(),
        BlockBuilder::new(),
    ];
    for block in attacks {
        let value = encoded(&token.append(block).unwrap());
        assert_eq!(
            inspect(&value),
            Err(Error::Profile),
            "structural rejection, not arbitrary Datalog authorization"
        );
    }
}

#[test]
fn native_chain_verification_rejects_tampering_and_wrong_or_unknown_roots() {
    let f = Fixture::new();
    assert!(matches!(
        VerifiedToken::from_token(f.token.value(), &BTreeMap::new()),
        Err(Error::Crypto)
    ));
    assert!(matches!(
        VerifiedToken::from_token(
            f.token.value(),
            &BTreeMap::from([(7, KeyPair::new().public())])
        ),
        Err(Error::Crypto)
    ));
    let mut envelope = biscuit_auth::format::schema::Biscuit::decode(
        raw(f.token.value(), f.roots[&7])
            .to_vec()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    envelope.authority.signature[0] ^= 1;
    let value = TokenValue::new(URL_SAFE.encode(envelope.encode_to_vec())).unwrap();
    assert!(
        inspect(&value).is_ok(),
        "inspection is deliberately not signature verification"
    );
    assert!(matches!(
        VerifiedToken::from_token(&value, &f.roots),
        Err(Error::Crypto)
    ));
}

#[test]
fn token68_padding_is_not_assumed_and_limits_are_enforced() {
    let f = Fixture::new();
    let bytes = raw(f.token.value(), f.roots[&7]).to_vec().unwrap();
    for value in [URL_SAFE.encode(&bytes), URL_SAFE_NO_PAD.encode(&bytes)] {
        assert!(VerifiedToken::from_token(&TokenValue::new(value).unwrap(), &f.roots).is_ok());
    }
    let oversized = TokenValue::new("A".repeat(22_000)).unwrap();
    assert_eq!(inspect(&oversized), Err(Error::Profile));
    let mut token = raw(f.token.value(), f.roots[&7]);
    for _ in 1..16 {
        token = token
            .append(
                BlockBuilder::new()
                    .check("check if time($t), $t < 2000")
                    .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(inspect(&encoded(&token)).unwrap().blocks, 16);
    token = token
        .append(
            BlockBuilder::new()
                .check("check if time($t), $t < 2000")
                .unwrap(),
        )
        .unwrap();
    assert_eq!(inspect(&encoded(&token)), Err(Error::Profile));
    for length in 0..128 {
        let garbage = TokenValue::new(URL_SAFE.encode(vec![0xff; length]))
            .unwrap_or_else(|_| TokenValue::new("AA").unwrap());
        assert!(inspect(&garbage).is_err());
    }
}

#[test]
fn access_descriptions_are_exact_and_unknown_shapes_are_refused() {
    let right = FileRight::new(ONE.into(), FileAction::Read).unwrap();
    let access = AccessItem::from(&right);
    assert_eq!(FileRight::try_from(&access).unwrap(), right);
    for json in [
        r#""files""#,
        r#"{"type":"unknown","locations":["https://rs.example/files/one"],"actions":["read"]}"#,
        r#"{"type":"gnap-biscuit-file-v1","locations":["https://rs.example/files/one"],"actions":["read","write"]}"#,
        r#"{"type":"gnap-biscuit-file-v1","locations":["https://rs.example/files/one"],"actions":["read"],"extension":true}"#,
    ] {
        let access: AccessItem = serde_json::from_str(json).unwrap();
        assert_eq!(FileRight::try_from(&access), Err(Error::Profile));
    }
    for uri in [
        "file:///tmp/one",
        "https://rs.example/one#fragment",
        "https://user@rs.example/one",
    ] {
        assert_eq!(
            FileRight::new(uri.into(), FileAction::Read),
            Err(Error::Profile)
        );
    }
}

#[test]
fn genuine_third_party_blocks_are_outside_the_profile() {
    let f = Fixture::new();
    let token = raw(f.token.value(), f.roots[&7]);
    let third_party = KeyPair::new();
    let response = token
        .third_party_request()
        .unwrap()
        .create_block(
            &third_party.private(),
            BlockBuilder::new()
                .check("check if time($t), $t < 1050")
                .unwrap(),
        )
        .unwrap();
    let extended = token
        .append_third_party(third_party.public(), response)
        .unwrap();
    assert!(Biscuit::from(extended.to_vec().unwrap(), f.roots[&7]).is_ok());
    assert_eq!(inspect(&encoded(&extended)), Err(Error::Profile));
}

#[test]
fn later_deadlines_cannot_relax_earlier_checks() {
    let f = Fixture::new();
    let child = f.descendant(Some(ONE), Some(1020));
    let grandchild =
        VerifiedToken::from_token(&child.attenuate(None, Some(1090)).unwrap(), &f.roots).unwrap();
    let h = headers(
        &f.signer,
        grandchild.value(),
        "GET",
        ONE,
        1020,
        Some("nonce"),
    );
    assert_eq!(
        authorize(&grandchild, &h, "GET", ONE, 1020),
        Err(Error::Denied)
    );
    let child_id = child.revocation_identifiers()[1].clone();
    let h = headers(
        &f.signer,
        grandchild.value(),
        "GET",
        ONE,
        1010,
        Some("nonce"),
    );
    assert_eq!(
        grandchild.authorize(
            &request(&h, "GET", ONE),
            &context(),
            &|_: &str, _: u64| true,
            &mut || Some(1010),
            &mut |ids| {
                assert!(ids.contains(&child_id));
                RevocationStatus::Revoked
            }
        ),
        Err(Error::Revoked)
    );
}

#[test]
fn preflight_rejects_nested_terms_scopes_counts_and_unknown_authority_shapes() {
    use biscuit_auth::format::schema::{self, term::Content};
    let f = Fixture::new();
    let original = raw(f.token.value(), f.roots[&7]).to_vec().unwrap();
    let modifications: &[fn(&mut schema::Block)] = &[
        |block| {
            block.facts[0].predicate.terms[0].content =
                Some(Content::Array(schema::Array { array: vec![] }));
        },
        |block| {
            block.facts[0].predicate.terms.push(schema::Term {
                content: Some(Content::Integer(0)),
            });
        },
        |block| {
            block.facts.push(block.facts[0].clone());
        },
        |block| {
            block.facts.clear();
        },
        |block| {
            block.facts[0].predicate.name = u64::MAX;
        },
        |block| {
            block.version = Some(6);
        },
        |block| {
            block.context = Some("unsupported".into());
        },
        |block| {
            block.scope.push(schema::Scope {
                content: Some(schema::scope::Content::ScopeType(0)),
            });
        },
        |block| {
            block.symbols.push(block.symbols[0].clone());
        },
        |block| {
            block.symbols.push("a".repeat(4097));
        },
        |block| {
            block.symbols.extend((0..129).map(|i| format!("extra-{i}")));
        },
    ];
    for modify in modifications {
        let mut envelope = schema::Biscuit::decode(original.as_slice()).unwrap();
        let mut block = schema::Block::decode(envelope.authority.block.as_slice()).unwrap();
        modify(&mut block);
        envelope.authority.block = block.encode_to_vec();
        let value = TokenValue::new(URL_SAFE.encode(envelope.encode_to_vec())).unwrap();
        assert_eq!(inspect(&value), Err(Error::Profile));
    }
    let child = f.descendant(None, Some(1050));
    let mut envelope =
        schema::Biscuit::decode(raw(child.value(), f.roots[&7]).to_vec().unwrap().as_slice())
            .unwrap();
    let mut block = schema::Block::decode(envelope.blocks[0].block.as_slice()).unwrap();
    block.checks.resize(3, block.checks[0].clone());
    envelope.blocks[0].block = block.encode_to_vec();
    assert_eq!(
        inspect(&TokenValue::new(URL_SAFE.encode(envelope.encode_to_vec())).unwrap()),
        Err(Error::Profile)
    );
}

#[test]
fn put_body_is_digest_bound_and_final_clock_is_fail_closed() {
    let f = Fixture::new();
    let authorization = format!("GNAP {}", f.token.value().as_str());
    let body = b"replacement contents";
    let digest = gnap_crypto::content_digest(body, gnap_crypto::DigestAlgorithm::Sha256);
    let message = Message {
        method: "PUT",
        target_uri: TWO,
        authorization: Some(&authorization),
        content_digest: Some(&digest),
        other: vec![],
    };
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
            Component::ContentDigest,
        ],
        created: 1010,
        keyid: f.signer.key_id().into(),
        nonce: Some("nonce".into()),
        tag: Tag::Gnap,
    };
    let (input, signature) = sign(&message, &input, &f.signer, "proof").unwrap();
    let headers = vec![
        ("Authorization".into(), authorization),
        ("Signature-Input".into(), input),
        ("Signature".into(), signature),
        ("Content-Digest".into(), digest),
    ];
    let request = SignedRequest {
        method: "PUT",
        target_uri: TWO,
        headers: &headers,
        body: Some(body),
    };
    assert_eq!(
        f.token.authorize(
            &request,
            &context(),
            &|_: &str, _: u64| true,
            &mut || Some(1010),
            &mut |_| RevocationStatus::Active
        ),
        Ok(())
    );
    let bad_body = SignedRequest {
        body: Some(b"attacker contents"),
        ..request
    };
    assert_eq!(
        f.token.authorize(
            &bad_body,
            &context(),
            &|_: &str, _: u64| true,
            &mut || Some(1010),
            &mut |_| panic!("bad body")
        ),
        Err(Error::Denied)
    );
    for (final_time, expected) in [(None, Error::Unavailable), (Some(1021), Error::Denied)] {
        let mut clock = [Some(1010), final_time].into_iter();
        assert_eq!(
            f.token.authorize(
                &request,
                &context(),
                &|_: &str, _: u64| true,
                &mut || clock.next().flatten(),
                &mut |_| RevocationStatus::Active
            ),
            Err(expected)
        );
    }
}

#[test]
fn issuer_rejects_invalid_times_keys_and_right_counts() {
    let signer = Ps256Signer::from_pkcs1_pem(PRIVATE, "client").unwrap();
    let issuer = Issuer::new(KeyPair::new(), 7, ISSUER.into(), AUDIENCE.into()).unwrap();
    let right = FileRight::new(ONE.into(), FileAction::Read).unwrap();
    let jwk = signer.public_jwk().unwrap();
    for rights in [
        vec![],
        vec![right.clone(), right.clone()],
        vec![right.clone(); 33],
    ] {
        assert!(matches!(
            issuer.mint(&rights, &jwk, 1000, 1100),
            Err(Error::Profile)
        ));
    }
    for (issued_at, expires_at) in [(1000, 1000), (1100, 1000), (1000, u64::MAX)] {
        assert!(matches!(
            issuer.mint(std::slice::from_ref(&right), &jwk, issued_at, expires_at),
            Err(Error::Profile)
        ));
    }
    let mut private_jwk = jwk.clone();
    private_jwk.insert("d".into(), serde_json::json!("AQAB"));
    assert!(matches!(
        issuer.mint(std::slice::from_ref(&right), &private_jwk, 1000, 1100),
        Err(Error::Crypto)
    ));
    let mut wrong_alg = jwk;
    wrong_alg.insert("alg".into(), serde_json::json!("RS256"));
    assert!(matches!(
        issuer.mint(&[right], &wrong_alg, 1000, 1100),
        Err(Error::Crypto)
    ));
}

#[test]
fn maximum_profile_counts_authorize_without_general_datalog() {
    let signer = Ps256Signer::from_pkcs1_pem(PRIVATE, "client").unwrap();
    let root = KeyPair::new();
    let roots = BTreeMap::from([(7, root.public())]);
    let issuer = Issuer::new(root, 7, ISSUER.into(), AUDIENCE.into()).unwrap();
    let rights: Vec<_> = (0..32)
        .map(|i| FileRight::new(format!("https://rs.example/files/{i}"), FileAction::Read).unwrap())
        .collect();
    let value = issuer
        .mint(&rights, &signer.public_jwk().unwrap(), 1000, 1100)
        .unwrap();
    let mut token = VerifiedToken::from_token(&value, &roots).unwrap();
    for _ in 1..16 {
        token = VerifiedToken::from_token(
            &token
                .attenuate(Some(rights[0].resource()), Some(1050))
                .unwrap(),
            &roots,
        )
        .unwrap();
    }
    assert_eq!(inspect(token.value()).unwrap().blocks, 16);
    let h = headers(
        &signer,
        token.value(),
        "GET",
        rights[0].resource(),
        1010,
        Some("nonce"),
    );
    assert_eq!(
        authorize(&token, &h, "GET", rights[0].resource(), 1010),
        Ok(())
    );
}

#[test]
fn authentication_scheme_obeys_http_grammar_without_normalizing_the_token() {
    let f = Fixture::new();
    for (prefix, allowed) in [
        ("gnap ", true),
        ("gNaP   ", true),
        ("Bearer ", false),
        ("GNAP\t", false),
    ] {
        let authorization = format!("{prefix}{}", f.token.value().as_str());
        let message = Message {
            method: "GET",
            target_uri: ONE,
            authorization: Some(&authorization),
            content_digest: None,
            other: vec![],
        };
        let input = SignatureInput {
            components: vec![
                Component::Method,
                Component::TargetUri,
                Component::Authorization,
            ],
            created: 1010,
            keyid: f.signer.key_id().into(),
            nonce: Some("nonce".into()),
            tag: Tag::Gnap,
        };
        let (input, signature) = sign(&message, &input, &f.signer, "proof").unwrap();
        let h = vec![
            ("Authorization".into(), authorization),
            ("Signature-Input".into(), input),
            ("Signature".into(), signature),
        ];
        assert_eq!(authorize(&f.token, &h, "GET", ONE, 1010).is_ok(), allowed);
    }
}

#[test]
fn a_nonce_less_signature_does_not_hide_a_later_acceptable_signature() {
    let f = Fixture::new();
    let mut combined = headers(&f.signer, f.token.value(), "GET", ONE, 1010, None);
    let mut later = headers(&f.signer, f.token.value(), "GET", ONE, 1010, Some("fresh"));
    // Labels are dictionary member names, not part of the signature base.
    later[1].1 = later[1].1.replacen("proof=", "second=", 1);
    later[2].1 = later[2].1.replacen("proof=", "second=", 1);
    combined.extend(later.into_iter().skip(1));
    let nonces = RefCell::new(HashSet::new());
    assert_eq!(
        f.token.authorize(
            &request(&combined, "GET", ONE),
            &context(),
            &|nonce: &str, _: u64| nonces.borrow_mut().insert(nonce.to_owned()),
            &mut || Some(1010),
            &mut |_| RevocationStatus::Active
        ),
        Ok(())
    );
    assert_eq!(*nonces.borrow(), HashSet::from(["fresh".to_owned()]));
}
