# Cryptographic test fixtures

`rfc9421-b12.pkcs1.pem` contains the example RSA private key
published in [RFC 9421, Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.2).
It is converted to PKCS#1 for the test implementation.

This private key is deliberately public. It is test material, not a deployment
credential, and must never protect real data. The HTTP delegation application
generates its own key at startup and does not load these fixtures.

## Notice for the RFC-derived fixtures

Copyright (c) 2024 IETF Trust and the persons identified as authors of the code.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
is permitted pursuant to, and subject to the license terms contained in, the
Revised BSD License set forth in Section 4.c of the IETF Trust's Legal Provisions
Relating to IETF Documents (https://trustee.ietf.org/license-info).

This file is a package-local copy of the repository's canonical fixture:

- [crates/gnap-crypto/tests/rfc9421-b12.pkcs1.pem](https://github.com/davlgd/gnap/blob/main/crates/gnap-crypto/tests/rfc9421-b12.pkcs1.pem)

It keeps tests usable outside a workspace checkout. The package
asset check verifies byte-for-byte equality with the canonical source. Change
the source and its copies together; do not invent independent fixture variants.
