# Human codes for secondary-device interaction

The SDK implements the `user_code` and `user_code_uri` start modes from
[RFC 9635 §§3.3.3–3.3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.3.3).
This is an SDK foundation, not a completed web application or a claim to the
Secondary Device interoperability profile. The browser entry component,
resource-owner authentication, consent screen, admission limits and actual
push delivery remain application work.

## Configure the AS

`AuthorizationServer::with_user_code_uri("https://as.example/code")` enables
both modes. The URI is stable: a code-only client knows it out of band, whereas
a `user_code_uri` client receives the exact URI in the response. It is not a
template and never contains the issued code. The entry component must serve a
GET page at that address; the SDK does not create an HTTP route.

This profile accepts an absolute HTTPS URI, or HTTP on an explicit loopback
host, up to 256 bytes. Query strings, fragments, percent encoding and `@` are
refused. These are deliberately narrower adapter choices, not GNAP's complete
URI rules. Prefer a URI that people can type: the RFC recommends 20 characters
or fewer. A loopback URI is only usable on the browser's own machine, not as the
address of another device on the network.

Discovery now lists `redirect` by default and adds both code modes after opt-in.
These are engine capabilities, not evidence that a deployment's pages or push
callbacks are reachable. A grant response includes only modes the client
offered; when both code modes are offered, they carry the same code. An offered
redirect also remains available, with a separate opaque handle.

## Generation, lookup and completion

Each code has eight Crockford base32 symbols: 40 bits of output space. A
dedicated draw from the AS's trusted `Nonces` source is hashed with the
`GNAP-user-code-v1` domain separator and a trailing zero byte. The first 40 bits
become eight five-bit symbol selections, without modulo bias. The source draw
must contain 1–512 bytes and be unpredictable; hashing a test counter is not
secure randomness. The existing `OsNonces` implementation supplies the source
for normal deployments.

Input normalization is case-insensitive, maps O to zero and I/L to one, removes
other characters outside the alphabet, and requires eight remaining symbols.
It accepts at most 128 UTF-8 bytes before allocating the result. For example,
`a l o b 2 3 4 5` means `A10B2345`. This normalization belongs to this profile;
it is not a validator for every code alphabet another GNAP implementation might
choose.

The trusted interaction component calls `resolve_user_code(input, now)` to get
the pending request's opaque handle. Resolution checks state and expiration
but neither authenticates the person nor consumes or approves the request.
After authenticating the owner as appropriate and obtaining consent for that
exact request, the component calls `complete_interaction(handle, now)`.
Only a successfully committed completion returns a finish directive.

Completion removes the code and the redirect handle together. Concurrent
attempts cannot both complete the same snapshot. A redirect completion also
invalidates the code, and a code-based completion invalidates the redirect.
The normal ten-minute AS interaction window applies. Expired entries are
refused, but the in-memory store retains their records and indexes until
replacement or explicit maintenance; expiration is not automatic garbage
collection. A caller-supplied clock must be reliable.

The existing finish rules still apply: a push or redirect directive must be
delivered before the client presents its validated interaction reference. With
no finish method, the component tells the owner to return to the client, which
polls while respecting the continuation wait. Returning a `Finish::Push` value
in a test is not evidence of HTTP push delivery or SSRF-safe routing.

## Storage and migration

Opt-in requires `UserCodeStore`, an optional extension of `GrantStore`.
`MemoryStorage`, `Arc` and borrowed adapters implement it. Ordinary stores do
not need the new trait, and `GrantSelector` has no new variant.

`GrantRecord` does gain an optional `user_code` field: existing struct literals
must initialize it to `None`. An adapter enabling codes must maintain its code
index in the same transaction as the grant, including creation, replacement,
completion, revocation and maintenance. The code is not an access, management
or continuation credential. It must disappear from both record and index when
the interaction is consumed.

Generation tries at most three candidates when a code is already indexed or
would occur in the entry URI. The store checks uniqueness again at publication.
A collision introduced concurrently at that boundary refuses the entire write;
it does not rerun authorization policy. A failed modification preserves the
previous grant and its code. Applications must handle an inconclusive response
without assuming that retry is idempotent.

## What the web consumer must still supply

The code is a request locator, not proof of the resource owner's identity. A
public entry page must limit both per-session and aggregate attempts, bound
pending grants and request sizes, and warn about excessive attempts. Forty bits
alone do not establish the RFC's required resistance to guessing during the
acceptance window. Admission policy and the number of simultaneously valid
codes matter too.

Use a POST form for code submission, without putting the code in the URL,
referrer or logs. Show the requested rights and require an explicit decision.
Unknown and expired codes should produce the same generic error and count
against the same attempt budget; neither may redirect to a client. The SDK
distinguishes expiry and storage failure for diagnostics, not public reflection.

A capable client should prefer `user_code_uri` over code-only operation and
communicate its URI unchanged, without adding the code as a parameter. A client
able to convey a long URI, such as a scannable one, should consider `redirect`
as the RFC recommends. None of these choices makes a code an authentication
factor.

## Evidence boundary

[SDK tests](../crates/gnap-as/tests/user_codes.rs) exercise both modes alone and
together with redirect, followed by polling or parsed redirect/push callbacks.
They cover normalization, expiry, renewal, maintenance, URI constraints and
bounded code generation. [Storage regressions](../crates/gnap-as/tests/user_codes/storage.rs)
force collisions immediately before creation and replacement, force both
completion readers to reach compare-and-exchange, and check index failure,
invalid candidates, adapter forwarding and revocation.

These exchanges use the actual client and AS SDKs with an in-memory transport.
They do not exercise a second browser, a public code-entry form, rate limits,
real owner authentication, deployed TLS or independent-vendor interoperability.
The delivery remains incomplete until a consumer exercises those applicable
application boundaries. In particular, this work alone does not supply the
push and assertion capabilities required by the full C2 profile.
