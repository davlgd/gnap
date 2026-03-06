/** JSON fixtures extracted from RFC 9635 examples. Identical to gnap-compliance fixtures. */

export const GRANT_REQUEST_SINGLE_TOKEN = `{
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
}`;

export const GRANT_REQUEST_MULTIPLE_TOKENS = `{
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
}`;

export const GRANT_REQUEST_WITH_INTERACTION = `{
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
}`;

export const GRANT_REQUEST_WITH_SUBJECT = `{
    "access_token": {
        "access": ["read"]
    },
    "client": "client-id",
    "subject": {
        "sub_id_formats": ["opaque", "iss_sub"],
        "assertion_formats": ["id_token"]
    }
}`;

export const GRANT_RESPONSE_WITH_TOKEN = `{
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
}`;

export const GRANT_RESPONSE_WITH_INTERACTION = `{
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
}`;

export const GRANT_RESPONSE_MULTIPLE_TOKENS = `{
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
}`;

export const GRANT_RESPONSE_USER_CODE = `{
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
}`;

export const GRANT_RESPONSE_USER_CODE_URI = `{
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
}`;

export const CONTINUE_REQUEST = `{
    "interact_ref": "4IFWWIKYBC2PQ6U56NL1"
}`;

export const ERROR_RESPONSE = `{
    "code": "user_denied",
    "description": "The RO denied the request"
}`;

export const ERROR_INVALID_REQUEST = `{
    "code": "invalid_request",
    "description": "The grant request was missing required fields"
}`;

export const GRANT_RESPONSE_WITH_ERROR = `{
    "error": {
        "code": "user_denied",
        "description": "The RO denied the request"
    }
}`;

export const GRANT_RESPONSE_WITH_ERROR_CODE = `{
    "error": "user_denied"
}`;
