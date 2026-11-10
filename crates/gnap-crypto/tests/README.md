# Cryptographic test fixtures

`rfc9421-b12.pkcs1.pem` and `rfc9421-b12.spki.pem` contain the example RSA key published in [RFC 9421, Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.2). The private key is converted to PKCS#1 for the test implementation; the public key uses SubjectPublicKeyInfo.

`rfc9421-b13.sec1.pem` and `rfc9421-b13.spki.pem` contain the example P-256 key of [Appendix B.1.3](https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.3), in SEC1 and SubjectPublicKeyInfo formats. `rfc9421-b14.pkcs8.pem` and `rfc9421-b14.spki.pem` contain the example Ed25519 key of [Appendix B.1.4](https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.4), in PKCS#8 and SubjectPublicKeyInfo formats, as the RFC publishes them.

`rfc9635-gnap-rsa.jwk.json` is the public RSA key `gnap-rsa` of the examples in [RFC 9635, Section 7.3.3](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.3). `rfc9635-7.3.3.detached-jws.txt` is the value of the `Detached-JWS` field in that section's example, and `rfc9635-7.3.4.attached-jws.txt` the content of the example in [Section 7.3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.4), with the line wrapping of RFC 8792 removed. Both sign with `RS256` under `gnap-rsa`, and both protected headers carry `"typ":"gnap-binding+jwsd"`, which matches neither the `gnap-binding-jwsd` nor the `gnap-binding-jws` that the sections require. The content printed in Section 7.3.3 doesn't hash to the signed payload either, so the tests use them as signatures, not as requests.

These private keys are deliberately public. They are test material, not deployment credentials, and must never protect real data. The HTTP delegation application generates its own key at startup and does not load these fixtures.

## Notice for the RFC-derived fixtures

Copyright (c) 2024 IETF Trust and the persons identified as authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to, and subject to the license terms contained in, the Revised BSD License set forth in Section 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents (<https://trustee.ietf.org/license-info>).
