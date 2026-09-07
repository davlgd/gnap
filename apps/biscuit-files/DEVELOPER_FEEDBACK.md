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

The SDK's optional token-key rotation adds an explicit binding to the encoder
context. Ignoring it would mint claims for the original grant key even after
the AS had accepted a new presentation key. The encoder now mints with that
binding, and the authoritative resource-nonce store selects the same key. The
bounded proof memory reserves both nonces atomically in its ordinary namespace.
The fixed demonstration policy permits this operation only after the SDK has
validated both linked proofs; the original grant identity does not change.

Generating replacement keys in the browser worker exposed an ownership gap:
the borrowed SDK API required storage outside the session. `rotate_key_owned`
lets the session retain an `Arc` without a leak or a global replacement key.
Resource requests use `signer_for`; explicit rejection probes retain only a
bounded set of old handles. Tests cover two key changes through the three
processes and distinguish an invalid old-key proof from a valid proof of a
retired native authority. A key-cycle test also prevents silently resetting
the old key's authoritative nonce history. Key generation is capped per session
and per process; the shared serial worker remains a demonstration limitation.

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

The remaining limits are deliberate and visible: one configured grant-client
identity, synthetic shared files, fixed immediate approval, authority-wide revocation,
bounded in-memory state. Local tests alone do not establish hosted behavior;
the [delivery guide](../../docs/biscuit-public-delivery.md) separates those checks.
The [public delivery record](https://github.com/davlgd/gnap/pull/32#issuecomment-5562885907)
documents HTTPS acceptance and maintenance for its identified revision.
Local attenuation preserves the client's key and is not RFC 9767 downstream
token derivation.

The SDK's former take/restore management sequence exposed another concurrency
problem: a failed operation could restore a record while another caller was
modifying it. The SDK now publishes a grant and all its token indexes in one
version-checked compare-and-swap. This consumer uses that contract directly;
the temporary engine-wide mutex is gone.

The adapter keeps only an inventory of grant IDs for retention and capacity,
not a second credential index. A shared lock covers SDK publication and the
native-identifier lookup plus resource-nonce reservation. Tests suspend a
resource decision while a real signed rotation is pending, then verify that
old indexes disappear together and that neither a stale snapshot nor a revoked
authority can be reactivated. Concurrent creation also respects the 64-authority
limit. Purging a grant never resets its client's resource reservations, and
storage unavailability remains an error rather than looking like absence.

HTTP integration caught another boundary detail: an explicit empty signed body
must not become an absent body. Dispatch now preserves `Some(empty)` when a
Content-Digest is present, and a real signed empty PUT is accepted as a file
clear. JSON extractor errors are also normalized so malformed field names or
values never appear in browser error responses.

Deployment uses an explicit choice between local key files and role-scoped
environment material. Both reject mixed or incomplete configuration, including
recognized variables belonging to another role. Injected lookup tests verify
the boundaries without modifying global process environment or printing keys.

Review also exposed a listener boundary: validating an HTTP loopback origin
did not help while the process listened on every interface, because a remote
caller can choose its Host header. Each role now binds cleartext local origins
only to their loopback interface; HTTPS deployments keep a network listener for
the upstream TLS proxy. The same listener policy needs a separate review in
the delegation demo and conformance web app; this example's correction does
not change those consumers.
