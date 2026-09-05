//! RFC rules the model enforces, one per test.
//!
//! Each test names the requirement it attests in its doc comment.

use gnap_registry::AccessTokenFlag;
use gnap_types::key::{KeyError, KeyObject};
use gnap_types::message::{Continue, GrantResponse};
use gnap_types::token::{
    AccessToken, AccessTokenError, AccessTokenResponse, Cardinality, TokenValue, TokenValueError,
};

fn discovery(endpoint: &str) -> gnap_types::message::AsDiscovery {
    serde_json::from_value(serde_json::json!({"grant_request_endpoint": endpoint})).unwrap()
}

/// RFC 9635 §9: HTTPS URL with host, optional port/path/query, no fragment.
#[test]
fn discovery_endpoint_accepts_https_url_components_without_normalizing() {
    for endpoint in [
        "https://as.example/gnap",
        "https://as.example:8443/gnap?tenant=a%2Fb&order=1",
        "https://[2001:db8::1]:8443/gnap?x=1",
        "HTTPS://AS.example/gnap",
    ] {
        assert_eq!(discovery(endpoint).validate_for(endpoint), Ok(()));
    }
    let response = discovery("https://as.example/gnap?tenant=a%2Fb");
    for different in [
        "https://as.example/gnap?tenant=a%2fb",
        "https://AS.example/gnap?tenant=a%2Fb",
        "https://as.example:443/gnap?tenant=a%2Fb",
        "https://as.example/gnap?tenant=a/b",
    ] {
        assert_eq!(
            response.validate_for(different),
            Err(gnap_types::message::DiscoveryError::EndpointMismatch)
        );
    }
}

#[test]
fn discovery_requires_an_https_host_and_valid_uri_grammar() {
    for endpoint in [
        "http://as.example/gnap",
        "http://127.0.0.1:8080/gnap",
        "https:/gnap",
        "https:///gnap",
        "https://:443/gnap",
        "https://?query",
        "https://as.example/gnap#fragment",
        "https://[invalid]/gnap",
        "https://[::1]evil/gnap",
        "https://as.example:invalid/gnap",
        "https://as.example/a b",
        "https://as.example/%zz",
        "mailto:as@example.com",
    ] {
        assert!(
            discovery(endpoint).validate_for(endpoint).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn discovery_development_exception_does_not_weaken_normative_validation() {
    for endpoint in [
        "http://localhost:8080/gnap",
        "http://127.0.0.1:8080/gnap",
        "http://127.1.2.3:8080/gnap",
        "http://[::1]:8080/gnap",
    ] {
        let response = discovery(endpoint);
        assert!(response.validate_for(endpoint).is_err());
        assert_eq!(response.validate_for_local_development(endpoint), Ok(()));
        assert_eq!(
            response.validate_for_local_development("http://localhost/other"),
            Err(gnap_types::message::DiscoveryError::EndpointMismatch)
        );
    }
    for endpoint in [
        "http://as.example/gnap",
        "http://localhost.attacker.example/gnap",
        "http://127.0.0.1.attacker.example/gnap",
        "http://10.0.0.1/gnap",
        "http://[::2]/gnap",
        "http://[::ffff:127.0.0.1]/gnap",
        "http://user@localhost/gnap",
    ] {
        assert!(
            discovery(endpoint)
                .validate_for_local_development(endpoint)
                .is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn discovery_requires_its_endpoint_but_preserves_extensions() {
    use gnap_types::message::AsDiscovery;
    for invalid in [
        "{}",
        r#"{"grant_request_endpoint":null}"#,
        r#"{"grant_request_endpoint":42}"#,
    ] {
        assert!(serde_json::from_str::<AsDiscovery>(invalid).is_err());
    }
    let response: AsDiscovery = serde_json::from_str(
        r#"{"grant_request_endpoint":"https://as.example/gnap","example_extension":true}"#,
    )
    .unwrap();
    assert_eq!(response.validate_for("https://as.example/gnap"), Ok(()));
    assert_eq!(response.extra["example_extension"], true);
}

/// GNAP-9635-§3.2.1-M30 — the client MUST reject a `bearer` token carrying `key`.
/// GNAP-9635-§3.2.1-M28 — "If the bearer flag is present, the access token is a
/// bearer token, and the key field in this response MUST be omitted."
#[test]
fn bearer_and_key_together_are_rejected() {
    let t: AccessToken =
        serde_json::from_str(r#"{"value":"ABC","access":["read"],"flags":["bearer"],"key":"k-1"}"#)
            .unwrap();
    assert_eq!(t.validate(), Err(AccessTokenError::BearerWithKey));

    // Without `key`, the same bearer token is valid.
    let t: AccessToken =
        serde_json::from_str(r#"{"value":"ABC","access":["read"],"flags":["bearer"]}"#).unwrap();
    assert_eq!(t.validate(), Ok(()));
    assert!(t.is_bearer());
}

/// GNAP-9635-§3.2.1-MN29 — "Flag values MUST NOT be included more than once."
#[test]
fn a_flag_may_not_appear_twice() {
    let t: AccessToken =
        serde_json::from_str(r#"{"value":"ABC","access":["read"],"flags":["durable","durable"]}"#)
            .unwrap();
    assert_eq!(
        t.validate(),
        Err(AccessTokenError::DuplicateFlag("durable".into()))
    );

    // The rule is about repetition, not about how many flags there are.
    let t: AccessToken = serde_json::from_str(
        r#"{"value":"ABC","access":["read"],"flags":["durable","x-experimental"]}"#,
    )
    .unwrap();
    assert_eq!(t.validate(), Ok(()));
}

/// GNAP-9635-§3.2.1-R08 — `access` is REQUIRED and MUST reflect the rights
/// associated with the issued token, so a token arriving without it tells the
/// client nothing about what it may do.
#[test]
fn an_issued_token_without_access_is_rejected() {
    let t: AccessToken = serde_json::from_str(r#"{"value":"ABC"}"#).unwrap();
    assert_eq!(t.validate(), Err(AccessTokenError::MissingAccess));
    assert!(t.validate().unwrap_err().to_string().contains("§3.2.1"));
}

/// GNAP-9635-§3.1-MN09 and GNAP-9635-§3.2.1-MN22 — the token "MUST be bound to
/// the client instance's key used in the request and MUST NOT be a bearer
/// token".
/// GNAP-9635-§3.1-MN10 and GNAP-9635-§3.2.1-MN23 — "As a consequence, the flags
/// array of this access token MUST NOT contain the string bearer, and the key
/// field MUST be omitted."
/// GNAP-9635-§3.1-MN11 and GNAP-9635-§3.2.1-MN24 — "This access token MUST NOT
/// have a manage field."
///
/// The model refuses those outright rather than letting them ride along in the
/// extension map. What it does not do is refuse `flags` itself: only the
/// `bearer` value is forbidden.
#[test]
fn a_bound_token_refuses_what_3_1_forbids_and_nothing_more() {
    use gnap_types::token::BoundToken;

    for forbidden in [
        r#"{"value":"ABC","flags":["bearer"]}"#,
        r#"{"value":"ABC","flags":["durable","bearer"]}"#,
        r#"{"value":"ABC","key":"k-1"}"#,
        r#"{"value":"ABC","manage":"https://as.example/token/1"}"#,
    ] {
        let err = serde_json::from_str::<BoundToken>(forbidden).unwrap_err();
        assert!(
            err.to_string().contains("§3.1"),
            "expected a §3.1 refusal for {forbidden}, got: {err}"
        );
    }

    // A duplicate flag is refused on this token too (§3.2.1).
    assert!(
        serde_json::from_str::<BoundToken>(r#"{"value":"ABC","flags":["durable","durable"]}"#)
            .is_err()
    );

    // Any other flag is legal, and so are extension fields.
    let ok: BoundToken =
        serde_json::from_str(r#"{"value":"ABC","flags":["durable"],"ext":1}"#).unwrap();
    assert_eq!(ok.flags, vec![AccessTokenFlag::Durable]);
    assert_eq!(ok.extra.len(), 1);
    assert_eq!(
        serde_json::to_value(&ok).unwrap(),
        serde_json::json!({"value":"ABC","flags":["durable"],"ext":1}),
        "the flags round-trip"
    );
}

/// GNAP-9635-§3.2.1-M01 — the value MUST be limited to the token68 set.
#[test]
fn token_value_respects_token68() {
    assert!(TokenValue::new("OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0").is_ok());
    assert!(TokenValue::new("B8CDFONP21-4TB8N6.BW7ONM").is_ok());
    assert!(
        TokenValue::new("abc+def/ghi~jkl_mno==").is_ok(),
        "padding and extended set accepted"
    );

    assert_eq!(
        TokenValue::new("abc def"),
        Err(TokenValueError::InvalidChar(' '))
    );
    assert_eq!(
        TokenValue::new("abc\"def"),
        Err(TokenValueError::InvalidChar('"'))
    );
    assert_eq!(TokenValue::new(""), Err(TokenValueError::Empty));
    assert_eq!(
        TokenValue::new("==="),
        Err(TokenValueError::Empty),
        "padding only"
    );
}

/// GNAP-9635-§3.2.1-MN31 and GNAP-9635-§3.2.2-MN03 — the response follows the request.
#[test]
fn response_cardinality_follows_the_request() {
    let object: AccessTokenResponse = serde_json::from_str(r#"{"value":"AAA"}"#).unwrap();
    assert_eq!(object.cardinality, Cardinality::Single);
    assert!(object.check_cardinality(Cardinality::Single).is_ok());

    let err = object.check_cardinality(Cardinality::Multiple).unwrap_err();
    assert!(err.to_string().contains("§3.2.2"), "{err}");

    // An array with one element stays an array: the very case §3.2.2 spells out.
    let array: AccessTokenResponse =
        serde_json::from_str(r#"[{"label":"t1","value":"AAA"}]"#).unwrap();
    assert_eq!(array.cardinality, Cardinality::Multiple);
    assert_eq!(array.tokens.len(), 1);
    let err = array.check_cardinality(Cardinality::Single).unwrap_err();
    assert_eq!(err.requested, Cardinality::Single);
    assert_eq!(err.answered, Cardinality::Multiple);
    assert!(err.to_string().contains("§3.2.1"), "{err}");
}

/// GNAP-9635-§7.1-M02 — a key sent by value has exactly one format.
/// GNAP-9635-§7.1-M03 — a JWK carries `alg` and `kid`, and `alg` is not `none`.
#[test]
fn a_key_is_presented_in_a_single_format() {
    let k: KeyObject = serde_json::from_str(r#"{"proof":"httpsig"}"#).unwrap();
    assert_eq!(k.validate(), Err(KeyError::NoFormat));

    let k: KeyObject = serde_json::from_str(
        r#"{"proof":"httpsig","jwk":{"alg":"PS256","kid":"k1"},"cert":"MIIC"}"#,
    )
    .unwrap();
    assert!(matches!(k.validate(), Err(KeyError::MultipleFormats(_))));

    let k: KeyObject = serde_json::from_str(r#"{"proof":"httpsig","jwk":{"kid":"k1"}}"#).unwrap();
    assert_eq!(k.validate(), Err(KeyError::JwkMissing("alg")));

    let k: KeyObject =
        serde_json::from_str(r#"{"proof":"httpsig","jwk":{"alg":"none","kid":"k1"}}"#).unwrap();
    assert_eq!(k.validate(), Err(KeyError::JwkAlgNone));

    let k: KeyObject =
        serde_json::from_str(r#"{"proof":"httpsig","jwk":{"alg":"PS256","kid":"k1"}}"#).unwrap();
    assert_eq!(k.validate(), Ok(()));
}

/// GNAP-9635-§3.1-M06 — an absent `wait` means five seconds.
#[test]
fn the_default_wait_is_five_seconds() {
    let c: Continue =
        serde_json::from_str(r#"{"uri":"https://as/continue","access_token":{"value":"AAA"}}"#)
            .unwrap();
    assert_eq!(c.effective_wait(), 5);

    let c: Continue = serde_json::from_str(
        r#"{"uri":"https://as/continue","access_token":{"value":"AAA"},"wait":30}"#,
    )
    .unwrap();
    assert_eq!(c.effective_wait(), 30);
}

/// Appendix D — an unregistered value is kept, it does not fail parsing.
#[test]
fn unregistered_values_survive_intact() {
    let t: AccessToken =
        serde_json::from_str(r#"{"value":"AAA","flags":["bearer","x-experimental"]}"#).unwrap();
    assert!(t.flags.contains(&AccessTokenFlag::Bearer));
    let inconnu = t
        .flags
        .iter()
        .find(|f| !f.is_registered())
        .expect("an unknown flag was expected");
    assert_eq!(inconnu.as_str(), "x-experimental");

    // And it comes back out unchanged.
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("x-experimental"), "{json}");
}

/// Appendix D — unknown message fields are preserved.
#[test]
fn extension_fields_are_preserved() {
    let src = r#"{"instance_id":"i-1","x_extension":{"foo":[1,2]}}"#;
    let r: GrantResponse = serde_json::from_str(src).unwrap();
    assert_eq!(r.extra.get("x_extension").unwrap()["foo"][1], 2);

    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("x_extension"), "extension field lost: {json}");
}

/// §3.6 — both error forms are equivalent, and the round trip is stable.
#[test]
fn an_error_serializes_in_the_form_received() {
    let e: gnap_types::GnapError = serde_json::from_str(r#""user_denied""#).unwrap();
    assert_eq!(serde_json::to_string(&e).unwrap(), r#""user_denied""#);

    let e: gnap_types::GnapError =
        serde_json::from_str(r#"{"code":"user_denied","description":"refuse"}"#).unwrap();
    assert_eq!(e.description.as_deref(), Some("refuse"));
    assert!(serde_json::to_string(&e).unwrap().contains("description"));
}

/// GNAP-9635-§5.3-MN09 — "The client instance MUST NOT include the client field
/// of the request, since the client instance is assumed not to have changed."
///
/// Letting it ride along in the extension map would carry to the AS a field the
/// RFC forbids, under the guise of an extension.
#[test]
fn a_continuation_request_refuses_the_client_field() {
    use gnap_types::message::ContinueRequest;

    let err = serde_json::from_str::<ContinueRequest>(
        r#"{"interact_ref":"4IFWWIKYBC2PQ6U56NL1","client":"client-541-ab"}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("§5.3"), "{err}");

    // §5.3 allows amending the user, and extension fields still ride along.
    let ok: ContinueRequest = serde_json::from_str(r#"{"user":"user-ref","ext":1}"#).unwrap();
    assert!(ok.user.is_some());
    assert_eq!(ok.extra.len(), 1);
}

/// GNAP-9635-§2.5.2-MN03 — "This URI MUST be an absolute URI and MUST NOT
/// contain any fragment component."
///
/// The requirement is about structure, so structure is what is checked: a
/// string made only of characters a URI may contain is not therefore a URI.
#[test]
fn a_callback_uri_is_checked_against_the_uri_grammar() {
    use gnap_types::interact::{FinishError, InteractFinish};

    let with_uri = |uri: &str| -> InteractFinish {
        serde_json::from_value(serde_json::json!({
            "method": "redirect", "uri": uri, "nonce": "VJLO6A4CATR0KRO"
        }))
        .unwrap()
    };

    for uri in [
        "https://client.example.net/cb",
        "https://client.example.net:8443/cb?state=1",
        "https://user:pw@client.example.net/cb",
        "https://[2001:db8::1]:8443/cb",
        "https://192.0.2.7/cb",
        "com.example.app:/callback",
        "com.example.app:",        // §4.3 allows path-empty; the handler decides
        "https://[v7.fe80::a]/cb", // IPvFuture, whose `v` is case-insensitive
        "https://[V7.fe80::a]/cb",
        "https://client.example.net/cb?caf%C3%A9=1",
    ] {
        assert_eq!(with_uri(uri).validate(), Ok(()), "{uri} should be a URI");
    }

    for uri in [
        "/cb",                               // relative
        "https://bad host/cb",               // a space is not a URI character
        "https://client.example.net/cb%ZZ",  // a truncated escape
        "https://[not-ipv6]/cb",             // an IP-literal that is not one
        "https://client.example.net:abc/cb", // a port that is not a number
        "https://cl|ent.example.net/cb",     // `|` is in no component
        "https://[::1]evil/cb",              // an IP-literal ends at its `]`
        "https://[::1]x",
        "https://[::1]:80x/cb", // a port is digits
        "https://[::1",         // the literal never closes
    ] {
        assert_eq!(
            with_uri(uri).validate(),
            Err(FinishError::Relative),
            "{uri} is not a URI"
        );
    }

    // §4.2.1 adds `hash` and `interact_ref`; a URI that already names either
    // would arrive with the parameter twice. Percent-encoding does not hide it.
    for uri in [
        "https://client.example.net/cb?hash=mine",
        "https://client.example.net/cb?a=1&interact_ref=x",
        "https://client.example.net/cb?h%61sh=mine",
        "https://client.example.net/cb?interact%5Fref=x",
    ] {
        assert_eq!(
            with_uri(uri).validate(),
            Err(FinishError::ReservedQueryParameter),
            "{uri} collides with what the AS adds"
        );
    }
}

/// GNAP-9635-§3.1-M08 — the continuation token "MUST be an object in the format
/// specified in Section 3.2.1", so the string form an access token request may
/// take is not one of its shapes.
/// GNAP-9635-§3.2.1-M21 — the token protecting the management API is the same
/// kind of object.
#[test]
fn a_bound_token_is_an_object_never_a_string() {
    use gnap_types::token::{BoundToken, TokenManage};

    assert!(
        serde_json::from_str::<BoundToken>(r#""80UPRY5NM33OMUKMKSKU""#).is_err(),
        "a bare string is not a §3.2.1 object"
    );
    assert!(serde_json::from_str::<BoundToken>(r#"{"value":"ABC"}"#).is_ok());

    assert!(
        serde_json::from_str::<TokenManage>(
            r#"{"uri":"https://as.example/token/1","access_token":"ABC"}"#
        )
        .is_err(),
        "nor is it one inside `manage`"
    );
}

/// GNAP-9635-§3.1-M02 — "This URI MUST be an absolute URI."
///
/// §3.1-M03 is why it matters: the client instance "MUST use this value exactly
/// as given", so a value it cannot use as it stands is a dead end.
#[test]
fn a_continuation_uri_must_be_absolute() {
    use gnap_types::message::{Continue, ContinueError};

    let with_uri = |uri: &str| -> Continue {
        serde_json::from_value(serde_json::json!({
            "uri": uri, "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}
        }))
        .unwrap()
    };

    assert_eq!(with_uri("https://as.example/continue").validate(), Ok(()));
    assert_eq!(
        with_uri("/continue").validate(),
        Err(ContinueError::UriNotAbsolute("/continue".into()))
    );
    assert_eq!(
        with_uri("https://as.example:port/continue").validate(),
        Err(ContinueError::UriNotAbsolute(
            "https://as.example:port/continue".into()
        ))
    );
}

/// GNAP-9635-§3.2.1-M17 — the management URI "MUST be an absolute URI".
/// GNAP-9635-§3.2.1-MN18 — it "MUST NOT include the value of the access token
/// being managed or the value of the access token used to protect the URI".
/// GNAP-9635-§3.2.1-MN25 — the managing token "MUST NOT have the same value as
/// the token it is managing".
///
/// A URI is not a secret: it travels through logs, referrer headers and browser
/// history. A token in one is a token given away.
#[test]
fn a_management_api_may_not_leak_the_tokens_it_governs() {
    use gnap_types::token::AccessToken;

    let managed = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0";
    let with_manage = |uri: &str, protecting: &str| -> AccessToken {
        serde_json::from_value(serde_json::json!({
            "value": managed,
            "access": ["dolphin-metadata"],
            "manage": {"uri": uri, "access_token": {"value": protecting}}
        }))
        .unwrap()
    };

    assert_eq!(
        with_manage("https://as.example/token/PRY5NM33O", "B8CDFONP21").validate(),
        Ok(())
    );

    assert_eq!(
        with_manage("/token/PRY5NM33O", "B8CDFONP21").validate(),
        Err(AccessTokenError::ManageUriNotAbsolute(
            "/token/PRY5NM33O".into()
        ))
    );
    assert_eq!(
        with_manage(&format!("https://as.example/token/{managed}"), "B8CDFONP21").validate(),
        Err(AccessTokenError::ManageUriLeaksToken(
            "the token it manages"
        ))
    );
    assert_eq!(
        with_manage("https://as.example/token/B8CDFONP21", "B8CDFONP21").validate(),
        Err(AccessTokenError::ManageUriLeaksToken(
            "the token that protects it"
        ))
    );
    assert_eq!(
        with_manage("https://as.example/token/PRY5NM33O", managed).validate(),
        Err(AccessTokenError::ManageTokenIsTheManagedToken)
    );
}

/// GNAP-9635-§2.3-M01 — "the client instance MUST identify itself by including
/// its client information in the client field of the request".
///
/// The field is not optional, so a request without it is not a grant request.
#[test]
fn a_grant_request_names_its_client() {
    use gnap_types::message::GrantRequest;

    assert!(
        serde_json::from_str::<GrantRequest>(r#"{"access_token":{"access":["read"]}}"#).is_err(),
        "a request with no client is not one"
    );
    assert!(serde_json::from_str::<GrantRequest>(r#"{"client":"client-541-ab"}"#).is_ok());
    assert!(
        serde_json::from_str::<GrantRequest>(
            r#"{"client":{"key":{"proof":"httpsig","jwk":{"kty":"RSA","kid":"k","alg":"PS256"}}}}"#
        )
        .is_ok(),
        "by value or by reference, but present"
    );
}

/// GNAP-9635-§2.3-MN09 — "The client instance MUST NOT send a symmetric key by
/// value in the key field of the request, as doing so would expose the key
/// directly instead of simply proving possession of it."
/// GNAP-9635-§7.1.2-MN03 — "Symmetric keys MUST NOT be passed by value from the
/// client instance to the AS."
#[test]
fn a_symmetric_key_is_never_sent_by_value() {
    // RFC 7518 §6.1 names the symmetric key type `oct`.
    let k: KeyObject = serde_json::from_str(
        r#"{"proof":"httpsig","jwk":{"kty":"oct","kid":"k","alg":"HS256","k":"c2VjcmV0"}}"#,
    )
    .unwrap();
    assert_eq!(k.validate(), Err(KeyError::SymmetricByValue));

    let k: KeyObject =
        serde_json::from_str(r#"{"proof":"httpsig","jwk":{"kty":"RSA","kid":"k","alg":"PS256"}}"#)
            .unwrap();
    assert_eq!(k.validate(), Ok(()));
}

/// GNAP-9635-§7.1-MN04 — "The `alg` parameter MUST NOT be `none`."
///
/// A key that declares no algorithm proves nothing, so a proof made with it
/// proves nothing either.
#[test]
fn a_key_may_not_declare_the_none_algorithm() {
    let k: KeyObject =
        serde_json::from_str(r#"{"proof":"httpsig","jwk":{"kty":"RSA","kid":"k","alg":"none"}}"#)
            .unwrap();
    assert_eq!(k.validate(), Err(KeyError::JwkAlgNone));
}

/// GNAP-9635-§2.1.1-MN06 — "Flag values MUST NOT be included more than once."
///
/// This is the request side; §3.2.1-MN29 is the same rule on the response.
#[test]
fn a_requested_flag_may_not_appear_twice() {
    use gnap_types::token::AccessTokenRequest;

    let err = serde_json::from_str::<AccessTokenRequest>(
        r#"{"access":["dolphin-metadata"],"flags":["split","split"]}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("more than once"), "{err}");

    assert!(serde_json::from_str::<AccessTokenRequest>(
        r#"{"access":["dolphin-metadata"],"flags":["split"]}"#
    )
    .is_ok());
}

/// GNAP-9635-§3.2.1-M12 — the token's `key` "MUST be an object or string in a
/// format described in Section 7.1".
#[test]
fn a_token_key_is_an_object_or_a_reference() {
    let by_reference: AccessToken =
        serde_json::from_str(r#"{"value":"ABC","access":["read"],"key":"k-1"}"#).unwrap();
    assert!(by_reference.key.is_some());

    let by_value: AccessToken = serde_json::from_str(
        r#"{"value":"ABC","access":["read"],
            "key":{"proof":"httpsig","jwk":{"kty":"RSA","kid":"k","alg":"PS256"}}}"#,
    )
    .unwrap();
    assert!(by_value.key.is_some());

    assert!(
        serde_json::from_str::<AccessToken>(r#"{"value":"ABC","access":["read"],"key":42}"#)
            .is_err(),
        "a number is neither"
    );
}

/// GNAP-9635-§2.3.2-M03 and GNAP-9635-§2.3.2-M05 — the two display URIs "MUST
/// be an absolute URI".
///
/// Both are shown to the RO on a page the AS serves. A relative one would
/// resolve against the AS's own origin, quietly turning the client's claim into
/// something the AS appears to be saying.
#[test]
fn displayable_client_information_carries_absolute_uris() {
    use gnap_types::client::{ClientDisplay, DisplayError};

    let display = |json: &str| -> ClientDisplay { serde_json::from_str(json).unwrap() };

    assert_eq!(
        display(r#"{"name":"Foo","uri":"https://client.example.net/about"}"#).validate(),
        Ok(())
    );
    // §2.3.2 accepts a `data:` logo, which is an absolute URI like any other.
    assert_eq!(
        display(r#"{"logo_uri":"data:image/png;base64,iVBORw0KGgo="}"#).validate(),
        Ok(())
    );
    assert_eq!(display(r#"{"name":"Foo"}"#).validate(), Ok(()));

    assert_eq!(
        display(r#"{"uri":"/about"}"#).validate(),
        Err(DisplayError::NotAbsolute {
            field: "uri",
            uri: "/about".into()
        })
    );
    assert_eq!(
        display(r#"{"logo_uri":"logo.png"}"#).validate(),
        Err(DisplayError::NotAbsolute {
            field: "logo_uri",
            uri: "logo.png".into()
        })
    );
}

/// GNAP-9635-§2.1.2-M03 — in a multiple-token request, every entry carries a
/// label and the labels are unique; otherwise "the AS MUST return an
/// `invalid_request` error".
/// GNAP-9635-§3.2.2-M01 — "Each object MUST have a unique label field,
/// corresponding to the token labels chosen by the client instance in the
/// request for multiple access tokens."
///
/// The label is the only thing that tells the tokens apart, on both sides.
#[test]
fn multiple_tokens_are_told_apart_by_unique_labels() {
    use gnap_types::token::AccessTokenRequest;

    // Requests.
    assert!(serde_json::from_str::<AccessTokenRequest>(
        r#"[{"label":"a","access":["read"]},{"label":"b","access":["write"]}]"#
    )
    .is_ok());
    for broken in [
        r#"[{"access":["read"]},{"label":"b","access":["write"]}]"#,
        r#"[{"label":"a","access":["read"]},{"label":"a","access":["write"]}]"#,
    ] {
        let err = serde_json::from_str::<AccessTokenRequest>(broken).unwrap_err();
        assert!(err.to_string().contains("label"), "{err}");
    }

    // Responses.
    assert!(serde_json::from_str::<AccessTokenResponse>(
        r#"[{"label":"a","value":"AAA"},{"label":"b","value":"BBB"}]"#
    )
    .is_ok());
    for broken in [
        r#"[{"value":"AAA"},{"label":"b","value":"BBB"}]"#,
        r#"[{"label":"a","value":"AAA"},{"label":"a","value":"BBB"}]"#,
    ] {
        let err = serde_json::from_str::<AccessTokenResponse>(broken).unwrap_err();
        assert!(err.to_string().contains("label"), "{err}");
    }
}

/// GNAP-9635-§2.1-M02 — `access_token` "MUST be an object (for a single access
/// token [...]) or an array of these objects (for multiple access tokens [...])".
/// GNAP-9635-§2.1.2-M01 — "Each object MUST conform to the request format for a
/// single access token request."
/// GNAP-9635-§3.2.2-M04 — when the client asked for multiple tokens, "the AS
/// MUST respond with a structure for multiple access tokens containing one
/// access token" even if it issues just one.
///
/// The shape carries meaning here: the same field means one token or several
/// depending on whether it is an object or an array, and the answer has to
/// mirror the question (§3.2.1, §3.2.2).
#[test]
fn the_shape_of_the_token_field_is_part_of_what_it_says() {
    use gnap_types::token::AccessTokenRequest;

    let single: AccessTokenRequest =
        serde_json::from_str(r#"{"access":["dolphin-metadata"]}"#).unwrap();
    assert_eq!(single.cardinality, Cardinality::Single);
    assert_eq!(single.tokens.len(), 1);

    let multiple: AccessTokenRequest =
        serde_json::from_str(r#"[{"label":"a","access":["read"]}]"#).unwrap();
    assert_eq!(
        multiple.cardinality,
        Cardinality::Multiple,
        "an array of one is still the multiple form"
    );

    // §2.1.2-M01 — an array entry is a single-token request, and is held to it.
    assert!(
        serde_json::from_str::<AccessTokenRequest>(r#"[{"label":"a"}]"#).is_err(),
        "`access` is required in each entry"
    );
    assert!(
        serde_json::from_str::<AccessTokenRequest>(r#""a-string""#).is_err(),
        "neither an object nor an array"
    );

    // §3.2.2-M04 — a single token answering a multiple request keeps the array.
    let answer: AccessTokenResponse =
        serde_json::from_str(r#"[{"label":"a","value":"AAA"}]"#).unwrap();
    assert_eq!(answer.tokens.len(), 1);
    assert!(answer.check_cardinality(Cardinality::Multiple).is_ok());
    assert!(
        answer.check_cardinality(Cardinality::Single).is_err(),
        "the shape must mirror the request, one token or not"
    );
}

/// GNAP-9635-§3.6-M01 — an error code's "value MUST be defined in the GNAP
/// Error Codes registry".
///
/// The registry is vendored and generated from, so a code outside it is not a
/// typo the model smooths over: it lands in `Unregistered` and stays visible.
#[test]
fn an_error_code_comes_from_the_registry() {
    use gnap_registry::ErrorCode;
    use gnap_types::error::GnapError;

    let known: GnapError = serde_json::from_str(r#""too_fast""#).unwrap();
    assert_eq!(known.code, ErrorCode::TooFast);

    let invented: GnapError = serde_json::from_str(r#""not_in_the_registry""#).unwrap();
    assert_eq!(
        invented.code,
        ErrorCode::Unregistered("not_in_the_registry".into()),
        "an unregistered code is carried as such, never mistaken for a known one"
    );
    assert!(
        !ErrorCode::REGISTERED.contains(&"not_in_the_registry"),
        "and the registry says so"
    );
}

/// GNAP-9635-§3.4-M14 — "all Subject Identifiers and assertions returned MUST
/// refer to the same party."
/// GNAP-9635-§2.2-M04 — "All identifiers in the `sub_ids` array MUST identify the
/// same subject", on the request side.
///
/// RFC 9635 §3.4 expects the formats to differ — "a returned assertion MAY use a
/// different Subject Identifier than other assertions" — so only what can be
/// proved is refused: within one issuer, the `iss_sub` pair of RFC 9493 §3.2.2
/// *is* the identity, and two `sub` values under one `iss` are two people.
/// Everything else is left alone, because someone can hold two email addresses
/// and `aliases` exists to group identifiers for one party.
#[test]
fn everything_said_about_a_subject_names_one_party() {
    use gnap_types::user::SubjectResponse;

    // Header and signature are fillers: the payload is what is read, and it is
    // read to compare two things one AS said, never to believe either.
    const HERE: &str = "eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9hcy5leGFtcGxlIiwgInN1\
                        YiI6ICJYVVQyTUZNMVhCSUtKS1NEVThRTSJ9.c2ln";
    const SOMEONE_ELSE: &str = "eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9hcy5leGFtcGxl\
                                IiwgInN1YiI6ICJTT01FT05FLUVMU0UifQ.c2ln";
    const ANOTHER_ISSUER: &str = "eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9vdGhlci5le\
                                  GFtcGxlIiwgInN1YiI6ICJTT01FT05FLUVMU0UifQ.c2ln";

    let subject = |json: String| -> SubjectResponse { serde_json::from_str(&json).unwrap() };
    let with_assertion = |value: &str| {
        format!(
            r#"{{"sub_ids":[{{"format":"iss_sub","iss":"https://as.example",
                              "sub":"XUT2MFM1XBIKJKSDU8QM"}}],
                 "assertions":[{{"format":"id_token","value":"{value}"}}]}}"#
        )
    };

    // The assertion names the same party as the identifier.
    assert_eq!(subject(with_assertion(HERE)).validate(), Ok(()));

    // The same issuer, a different subject: two people.
    let err = subject(with_assertion(SOMEONE_ELSE))
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("different parties"), "{err}");

    // A different issuer says nothing about this one, so nothing is claimed.
    assert_eq!(subject(with_assertion(ANOTHER_ISSUER)).validate(), Ok(()));

    // Two identifiers of a format whose identity this cannot settle are left
    // alone: a person may hold two email addresses.
    assert_eq!(
        subject(
            r#"{"sub_ids":[{"format":"email","email":"a@example.com"},
                           {"format":"email","email":"b@example.com"}]}"#
                .to_owned()
        )
        .validate(),
        Ok(())
    );

    // §2.2-M04 — the same rule on what the client sends about the end user.
    let user: gnap_types::user::UserObject = serde_json::from_str(
        r#"{"sub_ids":[{"format":"iss_sub","iss":"https://as.example","sub":"one"},
                       {"format":"iss_sub","iss":"https://as.example","sub":"two"}]}"#,
    )
    .unwrap();
    assert!(user.validate().is_err());
}

/// GNAP-9635-§8-MN06 — "The AS MUST NOT do any collation or normalization of
/// data types during comparison."
/// GNAP-9635-§8-R01 and GNAP-9635-§8-R03 — `type` is REQUIRED on every access
/// object.
///
/// What the model can attest is its half of §8-M04: the `type` an AS compares
/// is the one the client sent, byte for byte — no trimming, no case folding, no
/// Unicode normalization on the way in — and equality on the type is byte
/// equality. What a `Policy` then does with two such values is the
/// integrator's, and is classed as such in the perimeter.
#[test]
fn an_access_type_is_kept_byte_for_byte() {
    use gnap_types::access::AccessItem;

    let parse = |json: &str| -> AccessItem { serde_json::from_str(json).unwrap() };
    let kind = |json: &str| parse(json).kind().unwrap().to_owned();

    // Case, surrounding whitespace and Unicode form all survive.
    assert_eq!(kind(r#"{"type":"Photo-API"}"#), "Photo-API");
    assert_eq!(kind(r#"{"type":" photo-api "}"#), " photo-api ");
    assert_eq!(kind("{\"type\":\"caf\u{e9}\"}"), "caf\u{e9}");
    assert_eq!(kind("{\"type\":\"cafe\u{301}\"}"), "cafe\u{301}");

    // And so they are all different types.
    let distinct = [
        r#"{"type":"photo-api"}"#,
        r#"{"type":"Photo-API"}"#,
        r#"{"type":"photo-api "}"#,
        "{\"type\":\"caf\u{e9}\"}",
        "{\"type\":\"cafe\u{301}\"}",
    ]
    .map(parse);
    for (i, a) in distinct.iter().enumerate() {
        for (j, b) in distinct.iter().enumerate() {
            assert_eq!(a == b, i == j, "{a:?} vs {b:?}");
        }
    }

    // §8-R01, §8-R03 — an object without `type` is not an access right.
    let e = serde_json::from_str::<AccessItem>(r#"{"actions":["read"]}"#).unwrap_err();
    assert!(e.to_string().contains("`type` field is required"), "{e}");
}

/// The query is percent-encoded octets read as UTF-8 (RFC 3986 §2.1, §2.5).
///
/// GNAP-9635-§4.2.1-M05, RFC 9635 §4.2.1 — "the client instance MUST parse the
/// query parameters to extract the hash and interaction reference values."
///
/// An escape that does not decode is refused, not kept as text or skipped
/// over: either would hand the client a value the AS never sent, which it
/// would then validate a hash against.
#[test]
fn a_callback_query_is_percent_decoded_or_refused() {
    use gnap_types::interact::{CallbackError, InteractCallback};

    let cb = InteractCallback::from_redirect(
        "https://client.example.net/cb?other=1&hash=x%2Dy&interact_ref=r%41f+z",
    )
    .unwrap();
    assert_eq!(cb.hash, "x-y");
    assert_eq!(cb.interact_ref, "rAf z");

    // Multi-byte UTF-8 is one character, not two.
    let cb = InteractCallback::from_redirect("hash=caf%C3%A9&interact_ref=r").unwrap();
    assert_eq!(cb.hash, "caf\u{e9}");

    for bad in [
        "hash=%ZZ&interact_ref=r", // not hexadecimal
        "hash=%A&interact_ref=r",  // one digit short
        "hash=a%&interact_ref=r",  // nothing after the `%`
        "hash=%FF&interact_ref=r", // an octet that is not UTF-8
    ] {
        let e = InteractCallback::from_redirect(bad).unwrap_err();
        assert!(matches!(e, CallbackError::Malformed(_)), "{bad}: {e}");
    }
}
