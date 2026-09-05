//! The `httpsig` proof: GNAP's §7.3.1 requirements and the §7.3.1.1 rotation vector.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use gnap_crypto::httpsig::{
    check_gnap_requirements, sign, signature_base, verify, Component, Message, SignatureInput, Tag,
};
use gnap_crypto::proof::{ProofError, Signer};
use gnap_crypto::ps256::Ps256Signer;

/// The RSA key from Appendix B.1.2 of RFC 9421, converted to PKCS#1.
///
/// Its published PKCS#8 form carries the RSASSA-PSS OID
/// (`1.2.840.113549.1.1.10`), which `rsa::from_pkcs8_pem` rejects, so the
/// inner `RSAPrivateKey` is used instead.
const RSA_PKCS1: &str = include_str!("rfc9421-b12.pkcs1.pem");

const fn demo_message() -> Message<'static> {
    Message {
        method: "POST",
        target_uri: "https://server.example.com/gnap",
        content_digest: Some("sha-256=:q2XBmzRDCREcS2nWo/6LYwYyjrlN1bRfv+HKLbeGAGg=:"),
        authorization: None,
        other: Vec::new(),
    }
}

fn demo_input() -> SignatureInput {
    SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
        ],
        created: 1_618_884_473,
        keyid: "gnap-rsa".into(),
        nonce: Some("NAOEJF12ER2".into()),
        tag: Tag::Gnap,
    }
}

/// GNAP-9635-§7.3.1-M19 — the signature validates against the expected key.
/// Appendix C — both profiles mandate PS256, absent from RFC 9421's registry.
#[test]
fn sign_and_verify_with_ps256() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-rsa").unwrap();
    assert_eq!(signer.algorithm(), "PS256");

    let msg = demo_message();
    let input = demo_input();
    let (sig_input, sig) = sign(&msg, &input, &signer, "sig1").unwrap();

    assert!(sig_input.starts_with("sig1=("), "{sig_input}");
    assert!(sig.starts_with("sig1=:") && sig.ends_with(':'), "{sig}");

    // Replay the verifier's path: extract the value, decode, validate.
    let raw = sig_input.strip_prefix("sig1=").unwrap();
    let b64 = sig
        .strip_prefix("sig1=:")
        .unwrap()
        .strip_suffix(':')
        .unwrap();
    let bytes = STANDARD.decode(b64).unwrap();

    verify(&msg, &input.components, raw, &bytes, &signer.verifier())
        .expect("the produced signature should verify");
}

/// The invariant that neutralizes the upstream defect: the value emitted in
/// `Signature-Input` is exactly the base's `@signature-params` line.
#[test]
fn the_emitted_value_is_the_one_signed() {
    let input = demo_input();
    let raw = input.serialize().unwrap();
    let base = signature_base(&demo_message(), &input.components, &raw).unwrap();

    assert!(
        base.ends_with(&format!("\"@signature-params\": {raw}")),
        "\n{base}"
    );
    // And the requested order is preserved, which the `httpsig` path does not guarantee.
    assert!(
        raw.contains(r#";created=1618884473;nonce="NAOEJF12ER2";keyid="gnap-rsa";tag="gnap""#),
        "{raw}"
    );
}

/// GNAP-9635-§7.3.1.1 — the key rotation vector published by the RFC.
///
/// The new signature covers the old one's derived components
/// `"signature";key=` and `"signature-input";key=`, under the `gnap-rotate` tag.
#[test]
fn rfc_key_rotation_vector() {
    const OLD_SIG: &str = ":YdDJjDn2Sq8FR82e5IcOLWmmf6wILoswlnRcz+nM+e8xjFDpWS2YmiMYDqUdri2UiJsZx63T1z7As9Kl6HTGkQ==:";
    const OLD_INPUT: &str = r#"("@method" "@target-uri" "content-digest" "authorization");created=1618884475;keyid="test-key-ecc-p256";tag="gnap""#;

    let sig_comp = Component::DictionaryMember {
        field: "signature".into(),
        key: "old-key".into(),
    };
    let input_comp = Component::DictionaryMember {
        field: "signature-input".into(),
        key: "old-key".into(),
    };

    let msg = Message {
        method: "POST",
        target_uri: "https://server.example.com/token/PRY5NM33",
        content_digest: Some("sha-512=:Fb/A5vnawhuuJ5xk2RjGrbbxr6cvinZqd4+JPY85u/JNyTlmRmCOtyVhZ1Oz/cSS4tsYen6fzpCwizy6UQxNBQ==:"),
        authorization: Some("GNAP 4398.34-12-asvDa.a"),
        other: vec![
            (sig_comp.identifier(), OLD_SIG.into()),
            (input_comp.identifier(), OLD_INPUT.into()),
        ],
    };

    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
            Component::Authorization,
            sig_comp,
            input_comp,
        ],
        created: 1_618_884_480,
        keyid: "xyz-2".into(),
        nonce: None,
        tag: Tag::GnapRotate,
    };

    let raw = input.serialize().unwrap();
    let base = signature_base(&msg, &input.components, &raw).unwrap();

    // The base published in RFC 9635 §7.3.1.1, word for word.
    let expected = concat!(
        "\"@method\": POST\n",
        "\"@target-uri\": https://server.example.com/token/PRY5NM33\n",
        "\"content-digest\": sha-512=:Fb/A5vnawhuuJ5xk2RjGrbbxr6cvinZqd4+JPY85u/JNyTlmRmCOtyVhZ1Oz/cSS4tsYen6fzpCwizy6UQxNBQ==:\n",
        "\"authorization\": GNAP 4398.34-12-asvDa.a\n",
        "\"signature\";key=\"old-key\": :YdDJjDn2Sq8FR82e5IcOLWmmf6wILoswlnRcz+nM+e8xjFDpWS2YmiMYDqUdri2UiJsZx63T1z7As9Kl6HTGkQ==:\n",
        "\"signature-input\";key=\"old-key\": (\"@method\" \"@target-uri\" \"content-digest\" \"authorization\");created=1618884475;keyid=\"test-key-ecc-p256\";tag=\"gnap\"\n",
        "\"@signature-params\": (\"@method\" \"@target-uri\" \"content-digest\" \"authorization\" \"signature\";key=\"old-key\" \"signature-input\";key=\"old-key\");created=1618884480;keyid=\"xyz-2\";tag=\"gnap-rotate\"",
    );
    assert_eq!(base, expected, "\nrotation base diverges from the RFC");
}

/// GNAP-9635-§7.3.1-M04 — `@method` and `@target-uri` are always covered.
/// GNAP-9635-§7.3.1-M05 — `content-digest` is, as soon as there is content.
/// GNAP-9635-§7.3.1-M09 — `authorization` is, as soon as a token is presented.
#[test]
fn required_components_are_enforced() {
    let msg = demo_message();

    let without_method = SignatureInput {
        components: vec![Component::TargetUri, Component::ContentDigest],
        ..demo_input()
    };
    let e = check_gnap_requirements(&without_method, &msg).unwrap_err();
    assert!(matches!(e, ProofError::Coverage(_)));
    assert!(e.to_string().contains("@method"), "{e}");

    let without_digest = SignatureInput {
        components: vec![Component::Method, Component::TargetUri],
        ..demo_input()
    };
    let e = check_gnap_requirements(&without_digest, &msg).unwrap_err();
    assert!(e.to_string().contains("content-digest"), "{e}");

    let with_token = Message {
        authorization: Some("GNAP abc"),
        ..demo_message()
    };
    let e = check_gnap_requirements(&demo_input(), &with_token).unwrap_err();
    assert!(e.to_string().contains("authorization"), "{e}");

    // Complete: accepted.
    assert!(check_gnap_requirements(&demo_input(), &msg).is_ok());
}

/// GNAP-9635-§7.3.1-M11 — the `tag` parameter is `gnap`.
/// GNAP-9635-§7.3.1-M12 — the `created` parameter is present.
/// GNAP-9635-§7.3.1-MN16 — the `alg` parameter is never present.
#[test]
fn signature_parameters_follow_the_rfc() {
    let raw = demo_input().serialize().unwrap();
    assert!(raw.contains(r#"tag="gnap""#), "{raw}");
    assert!(raw.contains(";created=1618884473"), "{raw}");
    assert!(
        !raw.contains(";alg="),
        "the alg parameter is forbidden: {raw}"
    );

    let rotation = SignatureInput {
        tag: Tag::GnapRotate,
        ..demo_input()
    };
    assert!(rotation
        .serialize()
        .unwrap()
        .contains(r#"tag="gnap-rotate""#));
}

/// A covered component missing from the message must be reported, not ignored.
#[test]
fn a_covered_but_missing_component_is_reported() {
    let without_content = Message {
        content_digest: None,
        ..demo_message()
    };
    let e = signature_base(&without_content, &demo_input().components, "()").unwrap_err();
    assert!(matches!(e, ProofError::Base(_)));
    assert!(e.to_string().contains("content-digest"), "{e}");
}

/// A verifier reads the covered components back out of the received value, and
/// the round trip is the identity.
#[test]
fn covered_components_round_trip() {
    use gnap_crypto::httpsig::parse_covered_components;

    let input = demo_input();
    let parsed = parse_covered_components(&input.serialize().unwrap()).unwrap();
    assert_eq!(parsed, input.components);

    // The rotation shape, with its dictionary members, survives too.
    let raw = r#"("@method" "@target-uri" "content-digest" "authorization" "signature";key="old-key" "signature-input";key="old-key");created=1618884480;keyid="xyz-2";tag="gnap-rotate""#;
    let parsed = parse_covered_components(raw).unwrap();
    assert_eq!(parsed.len(), 6);
    assert_eq!(
        parsed[4],
        Component::DictionaryMember {
            field: "signature".into(),
            key: "old-key".into()
        }
    );

    // A malformed value is reported, and the message says what was expected.
    let e = parse_covered_components("no inner list")
        .unwrap_err()
        .to_string();
    assert!(e.contains("inner list"), "{e}");
    assert!(
        e.contains("§2.3"),
        "the diagnostic should cite the RFC: {e}"
    );

    // GNAP only ever parameterizes a component with `key` (§7.3.1.1); `bs` is
    // valid RFC 9421 but out of scope here, and saying so beats a bare refusal.
    let e = parse_covered_components(r#"("@method";bs)"#)
        .unwrap_err()
        .to_string();
    assert!(e.contains("key"), "{e}");
    assert!(e.contains("§7.3.1.1"), "{e}");
}

/// RFC 9651 §3.3.3 — a Structured Field string holds printable ASCII only.
///
/// This is not pedantry: a newline in a `keyid` would add a line to the
/// signature base, which is the canonicalization attack RFC 9421 §7.5.5
/// describes.
#[test]
fn a_newline_cannot_reach_the_signature_base() {
    for (field, bad) in [
        (
            "keyid",
            SignatureInput {
                keyid: "key\nid".into(),
                ..demo_input()
            },
        ),
        (
            "nonce",
            SignatureInput {
                nonce: Some("no\rnce".into()),
                ..demo_input()
            },
        ),
    ] {
        let e = bad.serialize().unwrap_err().to_string();
        assert!(
            e.contains(field),
            "the diagnostic should name the field: {e}"
        );
        assert!(e.contains("§3.3.3"), "and cite the rule: {e}");
    }

    // A dictionary key travels the same path (§7.3.1.1).
    let rotation = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::DictionaryMember {
                field: "signature".into(),
                key: "old\nkey".into(),
            },
        ],
        ..demo_input()
    };
    assert!(
        rotation.serialize().is_err(),
        "a newline in a dictionary key must be refused"
    );

    // Non-ASCII is refused too, for the same reason.
    let accented = SignatureInput {
        keyid: "clé".into(),
        ..demo_input()
    };
    assert!(accented.serialize().is_err());
}

/// RFC 9421 §2.5 step 2.1 — a component identifier occurs only once.
///
/// §7.5.7 describes repeating one as a way of padding a signature base.
#[test]
fn a_component_covered_twice_is_refused() {
    let input = SignatureInput {
        components: vec![Component::Method, Component::TargetUri, Component::Method],
        ..demo_input()
    };
    let raw = input.serialize().unwrap();
    let e = signature_base(&demo_message(), &input.components, &raw)
        .unwrap_err()
        .to_string();
    assert!(e.contains("@method"), "{e}");
    assert!(e.contains("only once"), "{e}");
    assert!(e.contains("§2.5"), "{e}");
}

/// RFC 9421 §2.5 step 4 — the signature base is ASCII.
#[test]
fn a_non_ascii_signature_base_is_refused() {
    // The offending character arrives through a field value rather than the
    // parameters, so it slips past the sf-string check and must be caught at
    // the end of the base.
    let message = Message {
        method: "POST",
        target_uri: "https://server.example.com/café",
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    };
    let components = [Component::Method, Component::TargetUri];
    let e = signature_base(
        &message,
        &components,
        r#"();created=1;keyid="k";tag="gnap""#,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("non-ASCII"), "{e}");
    assert!(e.contains("§2.5"), "{e}");
}

/// RFC 9421 §2.3 gives every signature parameter a Structured Fields type:
/// `created` is an Integer, `keyid`, `nonce`, `tag` and `alg` are Strings.
///
/// A verifier that trims quotes instead of parsing accepts `tag=gnap` unquoted,
/// keeps the backslashes of an escaped `keyid`, and reads an unbalanced quote as
/// if it closed — none of which is the value the signer signed.
#[test]
fn signature_parameters_are_read_with_their_types() {
    use gnap_crypto::httpsig::parse_signature_params;

    let params = parse_signature_params(
        r#"("@method");created=1618884473;expires=1618884775;keyid="test-key";tag="gnap""#,
    )
    .unwrap();
    assert_eq!(params.created, Some(1_618_884_473));
    assert_eq!(params.expires, Some(1_618_884_775));
    assert_eq!(params.keyid.as_deref(), Some("test-key"));
    assert_eq!(params.tag.as_deref(), Some("gnap"));
    assert_eq!(params.alg, None);

    // §4.2.5 — a backslash escapes only a backslash or a double quote, and the
    // escapes are removed by parsing.
    let params = parse_signature_params(r#"("@method");keyid="a\"b\\c""#).unwrap();
    assert_eq!(params.keyid.as_deref(), Some(r#"a"b\c"#));

    for malformed in [
        r#"("@method");tag=gnap"#,             // a bare token, not a string
        r#"("@method");created="1618884473""#, // a string, not an integer
        r#"("@method");expires="soon""#,       // same rule for expires
        r#"("@method");expires"#,              // a Boolean where an integer belongs
        r#"("@method");keyid="unbalanced"#,    // the quote never closes
        r#"("@method");keyid="a\nb""#,         // \n is not an escape here
        r#"("@method");alg"#,                  // a Boolean where a string belongs
        r#"("@method") keyid="k""#,            // no `;` before the parameter
    ] {
        assert!(
            parse_signature_params(malformed).is_err(),
            "`{malformed}` should not parse"
        );
    }

    // An unknown parameter is allowed, but it still has to be syntax: every
    // bare item type of RFC 9651 §3.3 is accepted, malformed values are not.
    for extensible in [
        r#"("@method");created=1;ext=42"#,           // integer
        r#"("@method");created=1;ext=4.25"#,         // decimal
        r#"("@method");created=1;ext="text""#,       // string
        r#"("@method");created=1;ext=token/x"#,      // token
        r#"("@method");created=1;ext=:AAAA:"#,       // byte sequence
        r#"("@method");created=1;ext=?1"#,           // boolean
        r#"("@method");created=1;ext=@1618884473"#,  // date
        r#"("@method");created=1;ext=%"caf%c3%a9""#, // display string
        r#"("@method");created=1;ext"#,              // boolean true, the bare form
    ] {
        assert!(
            parse_signature_params(extensible).is_ok(),
            "`{extensible}` should parse"
        );
    }

    for malformed in [
        r#"("@method");ext="unterminated"#,    // the quote never closes
        r#"("@method");ext=?2"#,               // not a boolean
        r#"("@method");ext=:not base64:"#,     // not a byte sequence
        r#"("@method");ext=4.2222"#,           // too many fractional digits
        r#"("@method");ext=1234567890123456"#, // more than 15 digits
        r#"("@method");EXT=1"#,                // a parameter name is lowercase
        r#"("@method");created=1234567890123456"#,
    ] {
        assert!(
            parse_signature_params(malformed).is_err(),
            "`{malformed}` should not parse"
        );
    }

    // A parameter given twice keeps its last value (RFC 9651 §4.2.3.2).
    let params = parse_signature_params(r#"("@method");keyid="first";keyid="second""#).unwrap();
    assert_eq!(params.keyid.as_deref(), Some("second"));
}

/// RFC 9421 §2.2 — a Dictionary member key is an `sf-string`, so it may hold
/// the characters that otherwise delimit the covered component list.
#[test]
fn a_dictionary_member_key_may_hold_delimiters() {
    use gnap_crypto::httpsig::parse_covered_components;

    let parsed = parse_covered_components(r#"("example-dict";key="a)b c";bad";key="x\"y\\z"")"#);
    assert!(
        parsed.is_err(),
        "a malformed identifier must be refused, got {parsed:?}"
    );

    let parsed = parse_covered_components(r#"("example-dict";key="a)b")"#).unwrap();
    assert_eq!(
        parsed,
        vec![Component::DictionaryMember {
            field: "example-dict".into(),
            key: "a)b".into(),
        }],
        "a `)` inside the key does not close the inner list"
    );

    let parsed = parse_covered_components(r#"("example-dict";key="x\"y\\z")"#).unwrap();
    assert_eq!(
        parsed,
        vec![Component::DictionaryMember {
            field: "example-dict".into(),
            key: r#"x"y\z"#.into(),
        }],
        "the escapes are removed, and only \\\\ and \\\" are escapes"
    );

    assert!(
        parse_covered_components(r#"("example-dict";key=noquotes)"#).is_err(),
        "a Dictionary member key is a string"
    );
}

/// RFC 9651 §4.2.2 — a Dictionary member repeated under the same key replaces
/// the earlier one; the field denotes one `sig1`, the last.
///
/// Matching the first instead lets a verifier accept a signature that does not
/// exist in the dictionary the field actually carries.
#[test]
fn a_repeated_dictionary_member_is_the_last_one() {
    use gnap_crypto::httpsig::parse_signatures;

    let outcomes = parse_signatures(
        r#"sig1=("@method");created=1;keyid="a";tag="gnap", sig1=("@target-uri");created=2;keyid="b";tag="gnap""#,
        "sig1=:AAAA:, sig1=:BBBB:",
    );
    assert_eq!(outcomes.len(), 1, "one key, one member");
    let parsed = outcomes[0].as_ref().expect("the member parses");
    assert!(
        parsed.raw_params.contains("@target-uri"),
        "the last member wins: {}",
        parsed.raw_params
    );
    assert_eq!(
        parsed.signature,
        vec![0x04, 0x10, 0x41],
        "the bytes are the last member's, `BBBB`"
    );
}

/// RFC 9651 §3.2 — a field that is not a Dictionary is not a field.
#[test]
fn a_malformed_dictionary_yields_one_refusal() {
    use gnap_crypto::httpsig::parse_signatures;

    for (input, signature) in [
        (r#"SIG1=("@method");created=1"#, "SIG1=:AAAA:"), // an sf-key is lowercase
        (r#"sig1=("@method");created=1,,"#, "sig1=:AAAA:"), // an empty member
    ] {
        let outcomes = parse_signatures(input, signature);
        assert_eq!(outcomes.len(), 1, "{input}");
        assert!(outcomes[0].is_err(), "{input} should be refused");
    }
}

/// RFC 9651 §4.2.2 — the Dictionary grammar, applied.
///
/// A field that does not parse is not a field; but a member that parses and is
/// merely the wrong type for `Signature-Input` is one candidate lost, not a
/// verdict on the message (RFC 9635 §7.3.1).
#[test]
fn the_dictionary_grammar_is_the_rfc_one() {
    use gnap_crypto::httpsig::parse_signatures;

    let good = r#"sig1=("@method");created=1;keyid="a";tag="gnap""#;

    for malformed in [
        format!("{good},"), // §4.2.2 step 2.10: a trailing comma fails
        r#"sig1 =("@method");created=1"#.to_owned(), // no whitespace around `=`
        format!("{good}, ,"), // an empty member is not a member
    ] {
        let outcomes = parse_signatures(&malformed, "sig1=:AAAA:");
        assert_eq!(outcomes.len(), 1, "{malformed}");
        assert!(outcomes[0].is_err(), "`{malformed}` should be refused");
    }

    // Whitespace after a member and after a comma is allowed.
    let outcomes = parse_signatures(&format!("bad=?1 ,\t{good}"), "bad=:AAAA:, sig1=:AAAA:");
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes[0].is_err() && outcomes[1].is_ok(),
        "the wrong-typed member fails alone: {outcomes:?}"
    );

    // A Boolean member with parameters is a valid Dictionary member and an
    // invalid Signature-Input value: the failure stays local to `bad`.
    let outcomes = parse_signatures(&format!("bad;ext=1, {good}"), "bad=:AAAA:, sig1=:AAAA:");
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes[0].is_err(), "{outcomes:?}");
    assert!(outcomes[1].is_ok(), "{outcomes:?}");

    // §4.2.7 — padding is not what makes a Byte Sequence valid.
    let outcomes = parse_signatures(good, "sig1=:AAA:");
    assert!(outcomes[0].is_ok(), "{outcomes:?}");
}

/// GNAP-9635-§7.3.1-M03 — "When the proofing method is specified in string
/// form, the signing algorithm MUST be derived from the key material (such as
/// using the JWS algorithm in a JWK formatted key), and the content digest
/// algorithm MUST be sha-256."
///
/// Both halves are structural here. The algorithm never appears in the message
/// — §7.3.1 forbids the `alg` parameter — so it can only come from the key: the
/// signer carries it and names it. And `Content-Digest` is emitted as `sha-256`
/// and nothing else.
#[test]
fn the_algorithm_comes_from_the_key_and_the_digest_is_sha_256() {
    use gnap_crypto::digest::{content_digest, DigestAlgorithm};
    use gnap_crypto::proof::{Signer, Verifier};
    use gnap_crypto::ps256::Ps256Signer;

    let signer =
        Ps256Signer::from_pkcs1_pem(include_str!("rfc9421-b12.pkcs1.pem"), "gnap-demo").unwrap();

    // The key material decides, and says so on both sides.
    assert_eq!(signer.algorithm(), "PS256");
    assert_eq!(signer.verifier().algorithm(), signer.algorithm());

    // §7.3.1 — "The explicit alg signature parameter MUST NOT be included", so
    // the emitted parameters carry no algorithm at all.
    let input = SignatureInput {
        components: vec![Component::Method, Component::TargetUri],
        created: 1_618_884_473,
        keyid: signer.key_id().to_owned(),
        nonce: None,
        tag: Tag::Gnap,
    };
    let raw = input.serialize().unwrap();
    assert!(!raw.contains("alg"), "{raw}");

    // The content digest algorithm is `sha-256`, named in the field itself.
    let digest = content_digest(b"{}", DigestAlgorithm::Sha256);
    assert!(digest.starts_with("sha-256=:"), "{digest}");
}

/// GNAP-9635-§7.3.1-M04 names the components a signature MUST cover; it does
/// not cap them, and RFC 9421 lets a signer cover any field it likes. So a
/// verifier has to be able to read a covered field out of the message, and
/// read it the way §2.1 says: every instance, trimmed, joined by `, `.
#[test]
fn an_extra_covered_field_is_read_from_the_message() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-rsa").unwrap();
    let mut input = demo_input();
    input.components.push(Component::Field("X-Extra".into()));

    // What the signer covered: the two instances, combined.
    let mut covered = demo_message();
    covered.other = vec![("\"x-extra\"".into(), "a, b".into())];
    let (sig_input, sig) = sign(&covered, &input, &signer, "sig1").unwrap();
    let raw = sig_input.strip_prefix("sig1=").unwrap();
    let sig = STANDARD
        .decode(
            sig.strip_prefix("sig1=:")
                .unwrap()
                .strip_suffix(':')
                .unwrap(),
        )
        .unwrap();

    // The verifier only has the message's headers, with their whitespace and
    // their own casing of the name.
    let headers = [
        ("Content-Type", "application/json"),
        ("X-EXTRA", "  a\t"),
        ("x-extra", "b "),
    ];
    let lookup = |name: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
            .collect()
    };
    let received = demo_message().with_fields(&input.components, lookup);
    verify(&received, &input.components, raw, &sig, &signer.verifier()).expect("the field is read");

    // Covered but absent from the message: the base cannot be built (§2.5).
    let bare = demo_message().with_fields(&input.components, |_| Vec::<&str>::new());
    let e = verify(&bare, &input.components, raw, &sig, &signer.verifier()).unwrap_err();
    assert!(e.to_string().contains("missing from the message"), "{e}");

    // Present with an empty value is not absent (§2.1): the component line is
    // `"x-extra": ` and a signature over it verifies.
    let mut empty = demo_message();
    empty.other = vec![("\"x-extra\"".into(), String::new())];
    let (sig_input, sig) = sign(&empty, &input, &signer, "sig1").unwrap();
    let raw = sig_input.strip_prefix("sig1=").unwrap();
    let sig = STANDARD
        .decode(
            sig.strip_prefix("sig1=:")
                .unwrap()
                .strip_suffix(':')
                .unwrap(),
        )
        .unwrap();
    let received = demo_message().with_fields(&input.components, |_| vec![""]);
    assert_eq!(received.other, empty.other);
    verify(&received, &input.components, raw, &sig, &signer.verifier())
        .expect("an empty instance is still an instance");
}
