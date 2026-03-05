//! JSON fixtures extracted from RFC 9635 examples.
//! Used as canonical test vectors for compliance validation.

/// RFC 9635 Section 2 — Grant request with single access token (simplified).
pub const GRANT_REQUEST_SINGLE_TOKEN: &str = r#"{
    "access_token": {
        "access": [
            {
                "type": "photo-api",
                "actions": ["read", "write", "delete"],
                "locations": ["https://server.example.net/", "https://resource.local/other"],
                "datatypes": ["metadata", "images"]
            }
        ]
    },
    "client": {
        "key": {
            "proof": "httpsig",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "dGVzdC1rZXktdmFsdWUtMTIzNDU2Nzg5MGFi",
                "kid": "gnap-rfc-example"
            }
        }
    }
}"#;

/// RFC 9635 Section 2 — Grant request with multiple access tokens.
pub const GRANT_REQUEST_MULTIPLE_TOKENS: &str = r#"{
    "access_token": [
        {
            "access": [
                {
                    "type": "photo-api",
                    "actions": ["read"]
                }
            ],
            "label": "token1"
        },
        {
            "access": [
                {
                    "type": "walrus-access",
                    "actions": ["read", "write"]
                }
            ],
            "label": "token2"
        }
    ],
    "client": "client-instance-id-12345"
}"#;

/// RFC 9635 Section 2 — Grant request with interaction.
pub const GRANT_REQUEST_WITH_INTERACTION: &str = r#"{
    "access_token": {
        "access": [
            {
                "type": "photo-api",
                "actions": ["read", "write"]
            }
        ]
    },
    "client": {
        "key": {
            "proof": "httpsig",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "dGVzdC1rZXktdmFsdWUtMTIzNDU2Nzg5MGFi",
                "kid": "gnap-rfc-example"
            }
        },
        "display": {
            "name": "My Client Display Name",
            "uri": "https://client.example.net"
        }
    },
    "interact": {
        "start": ["redirect"],
        "finish": {
            "method": "redirect",
            "uri": "https://client.example.net/return/123455",
            "nonce": "LKLTI25DK82FX4T4QFZC"
        }
    }
}"#;

/// RFC 9635 Section 2 — Grant request with subject information.
pub const GRANT_REQUEST_WITH_SUBJECT: &str = r#"{
    "access_token": {
        "access": ["read"]
    },
    "client": "client-id",
    "subject": {
        "sub_id_formats": ["opaque", "iss_sub"],
        "assertion_formats": ["id_token"]
    }
}"#;

/// RFC 9635 Section 3 — Grant response with access token.
pub const GRANT_RESPONSE_WITH_TOKEN: &str = r#"{
    "continue": {
        "access_token": {
            "value": "80UPRY5NM33OMUKMKSKU"
        },
        "uri": "https://server.example.com/continue/VGJKPTKC50"
    },
    "access_token": {
        "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
        "manage": {
            "uri": "https://server.example.com/token/PRY5NM33O",
            "access_token": {
                "value": "B8CDFONP21-4TB8N6.BW7ONM"
            }
        },
        "access": [
            {
                "type": "photo-api",
                "actions": ["read", "write", "delete"],
                "locations": ["https://server.example.net/"],
                "datatypes": ["metadata", "images"]
            }
        ]
    }
}"#;

/// RFC 9635 Section 3 — Grant response with interaction redirect.
pub const GRANT_RESPONSE_WITH_INTERACTION: &str = r#"{
    "continue": {
        "access_token": {
            "value": "80UPRY5NM33OMUKMKSKU"
        },
        "uri": "https://server.example.com/continue/VGJKPTKC50",
        "wait": 30
    },
    "interact": {
        "redirect": "https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ",
        "finish": "MBDOFXG4Y5CVJCX821LH"
    }
}"#;

/// RFC 9635 Section 3 — Grant response with multiple tokens.
pub const GRANT_RESPONSE_MULTIPLE_TOKENS: &str = r#"{
    "continue": {
        "access_token": {
            "value": "80UPRY5NM33OMUKMKSKU"
        },
        "uri": "https://server.example.com/continue/VGJKPTKC50"
    },
    "access_token": [
        {
            "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
            "label": "token1",
            "access": [
                {
                    "type": "photo-api",
                    "actions": ["read"]
                }
            ]
        },
        {
            "value": "UFGLO2FDAFG7VGZZPJ3IZEMN21EVU71FHCARP4J1",
            "label": "token2",
            "access": [
                {
                    "type": "walrus-access",
                    "actions": ["read", "write"]
                }
            ]
        }
    ]
}"#;

/// RFC 9635 Section 3 — Grant response with user_code (plain string per Section 3.3.3).
pub const GRANT_RESPONSE_USER_CODE: &str = r#"{
    "continue": {
        "access_token": {
            "value": "80UPRY5NM33OMUKMKSKU"
        },
        "uri": "https://server.example.com/continue/VGJKPTKC50",
        "wait": 30
    },
    "interact": {
        "user_code": "A1BC-3DFF",
        "finish": "MBDOFXG4Y5CVJCX821LH"
    }
}"#;

/// RFC 9635 Section 3 — Grant response with user_code_uri (object per Section 3.3.4).
pub const GRANT_RESPONSE_USER_CODE_URI: &str = r#"{
    "continue": {
        "access_token": {
            "value": "80UPRY5NM33OMUKMKSKU"
        },
        "uri": "https://server.example.com/continue/VGJKPTKC50",
        "wait": 30
    },
    "interact": {
        "user_code_uri": {
            "code": "A1BC-3DFF",
            "uri": "https://server.example.com/device"
        },
        "finish": "MBDOFXG4Y5CVJCX821LH"
    }
}"#;

/// RFC 9635 Section 5.1 — Continuation request with interact_ref.
pub const CONTINUE_REQUEST: &str = r#"{
    "interact_ref": "4IFWWIKYBC2PQ6U56NL1"
}"#;

/// RFC 9635 Section 3.6 — Error response (object form).
pub const ERROR_RESPONSE: &str = r#"{
    "code": "user_denied",
    "description": "The RO denied the request"
}"#;

/// RFC 9635 Section 3.6 — Error: invalid_request (object form).
pub const ERROR_INVALID_REQUEST: &str = r#"{
    "code": "invalid_request",
    "description": "The grant request was missing required fields"
}"#;

/// RFC 9635 Section 3.6 — Error in a grant response (wrapped in error field).
pub const GRANT_RESPONSE_WITH_ERROR: &str = r#"{
    "error": {
        "code": "user_denied",
        "description": "The RO denied the request"
    }
}"#;

/// RFC 9635 Section 3.6 — Error as a string code in a grant response.
pub const GRANT_RESPONSE_WITH_ERROR_CODE: &str = r#"{
    "error": "user_denied"
}"#;
