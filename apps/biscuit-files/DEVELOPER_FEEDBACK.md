# What this consumer exposed

This example is an integration exercise, not an independent conformance test.
It runs the same SDK on both sides, but splits the AS, RS and client into real
HTTP processes and injects failures between them.

The token encoder hook is sufficient for this profile: approved rights convert
directly to exact resource/action pairs, the selected lifetime becomes Biscuit
claims, and a native authority identifier can stay beside the token record.
The adapter rejects unresolved client references, unsupported proof methods,
missing lifetimes and issuer mismatches. It does not infer authorization from
the encoded token or mutate the AS store from inside the encoder.

The first missing client capability was a public request-signing operation for
an explicitly supplied token. An attenuated descendant is not the original
token held by `Session`, and file writes are not JSON. The new SDK
`sign_request` helper handles both, while also signing the RS's separate check
request with no access token. There is no application copy of signature-base
construction.

Native revocation is more than a token parser. The RS needs current,
authenticated authority state. The example uses the AS's actual token store,
an RS-specific signing key and correlated, uncached HTTPS responses. Rotation
and revocation tests sign fresh requests to distinguish retired-token rejection
from rejection of an already spent request nonce.

The three-process boundary exposed a restart defect: an RS-only restart lost
local replay history without removing the AS's live tokens. The application
now reserves each resource nonce at the AS, atomically with its authority check.
The reservation is scoped to the client key, not an authority or an RS instance.
It is retained across RS restart and token rotation; AS restart removes both
reservations and the authorities they protect.

That correction required the Biscuit verifier to give its live callback the
parameters of the signature it actually accepted. Taking the first nonce from
the input headers would be wrong when several signatures are present. The
callback now returns a one-use `LiveDecision`, after cryptography and Datalog,
with a final clock check still performed before allowing the file operation.
The application endpoint is consequently named `/resource-check`, not a token
status endpoint. Its exact body is `authority`, `nonce`, `created`; its response
is only `request_allowed`, correlated to the RS-to-AS request through headers.

Real process tests cover replay after RS restart and a race between two RS
instances. Retention uses a monotonic clock, global and per-key quotas, an
explicit clock-offset budget and refusal on detected clock failure. None of
this makes the application channel RFC 9767 introspection.

The remaining limits are deliberate and visible: one configured client key,
synthetic shared files, fixed immediate approval, authority-wide revocation,
bounded in-memory state and no public deployment claim. Local attenuation
preserves the client's key and is not RFC 9767 downstream token derivation.

The current SDK's take/restore management sequence also has a concurrency
limitation: a failed operation can restore a record while another SDK caller
is concurrently modifying it. This application serializes its own management
dispatch with an engine mutex, which mitigates that path here; it does not
establish that the SDK store contract is race-free for other consumers. The
SDK's compare-and-swap migration is a separate fix, not something this example
can claim to provide through its application lock.

HTTP integration caught another boundary detail: an explicit empty signed body
must not become an absent body. Dispatch now preserves `Some(empty)` when a
Content-Digest is present, and a real signed empty PUT is accepted as a file
clear. JSON extractor errors are also normalized so malformed field names or
values never appear in browser error responses.

Deployment uses an explicit choice between local key files and role-scoped
environment material. Both reject mixed or incomplete configuration, including
recognized variables belonging to another role. Injected lookup tests verify
the boundaries without modifying global process environment or printing keys.
