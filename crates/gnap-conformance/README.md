# gnap-conformance

Selected checks of GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) and GNAP resource-server ([RFC 9767](https://www.rfc-editor.org/rfc/rfc9767)) messages and servers, as a library and a command line. Each check names the clause it relies on; passing the selected checks isn't conformance, and no report is a certification.

Install the command with `cargo install gnap-conformance`, or add the library with `cargo add gnap-conformance`.

## Check a server from the command line

`gnap-conformance` runs selected checks against an authorization server you name, and prints a report. Install it from crates.io:

```bash
cargo install gnap-conformance
gnap-conformance discover https://as.example/gnap
gnap-conformance probe https://as.example/gnap --json
```

`discover` sends `OPTIONS` to the grant endpoint and checks its discovery document ([RFC 9635 §9](https://www.rfc-editor.org/rfc/rfc9635.html#section-9)), without fetching any link it announces. `probe` sends a malformed initial grant request, which carries no client or proof, and checks the refusal ([§3.6](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6)). Each command sends only that request, through the bounded transport of this crate: no proxy, redirect, or retry, public addresses pinned, and bounded time and sizes.

`lifecycle` runs one grant from request to revocation with a key it generates in memory, never shown or stored:

```bash
gnap-conformance lifecycle https://as.example/gnap \
  --proof jwsd --alg EdDSA --access read --resource https://rs.example/files --rotate-key
```

`--proof` is `httpsig`, `jws`, or `jwsd`, and `--alg` an algorithm the method takes: PS256, ES256, or EdDSA for `httpsig`, and RS256, ES256, or EdDSA for the JOSE proofs. `--access` names a requested right, as a string or a JSON object, up to eight times. The scenario requests a token with a redirect start and no finish. When the grant is pending, it shows the interaction link on standard error, never follows it, and polls for up to `--wait` seconds (120 by default, at most 600). Then it rotates the token's value, changes its key with `--rotate-key` when the AS announces key rotation, and revokes the token. Cleanup, with a budget of its own, revokes a token the scenario still holds and then the grant; an AS without a continuation API leaves no grant to revoke, which RFC 9635 allows. With `--resource`, it reads the resource with the token, proven with its key, after issuance, then with the last token and key just before revocation, and once more after it, each time with a fresh proof: a refusal after revocation counts only when the read before it was accepted.

The scenario sends only what it was given, and the exact continuation and management URIs that accepted answers name on the grant endpoint's origin: another origin is reported as outside its profile, never followed. An AS that refuses the client, or a resource owner who denies the request with `user_denied`, ends the scenario without a failure: those are policies and results, not deviations, and another GNAP error to a continuation leaves the scenario inconclusive. An interrupt stops the scenario before its next request and cleans up; a second one quits. The report records the run's profile, which is the proof method, the algorithm, the number of rights, and whether the scenario reads a resource or changes the key, without the rights or the resource URI. It lists every step of the scenario, and a step it didn't reach is skipped. If an answer is lost, the grant may remain at the AS.

The endpoint is HTTPS on port 443 with a public DNS name, without credentials, query, or fragment; `--allow-loopback-http` admits a local `http://localhost`, `127.0.0.1`, or `[::1]` server. Each check is `passed`, `failed`, `inconclusive`, `skipped`, or `not_applicable`, with the clause it relies on. `--json` prints the report in the `gnap-conformance/1` schema. The exit code is 0 when every selected check that applied passed, 1 when one failed, and 2 for a usage error or when no check could be decided. Passing selected checks isn't conformance or certification.

Its HTTPS requests go through rustls, which loads the certificate authorities of the system on Linux and fails if it finds none. Building it needs a C compiler, for the AWS-LC cryptographic backend.

## Use the library

`analyze` checks one captured message offline, and fetches nothing. The `discovery` and `probe` modules check a captured discovery document and a captured answer to a malformed grant request. The `scenario` module runs the lifecycle scenario over any `HttpTransport`, and `net` provides the command line's bounded transport. The [diagnostic workbench](https://github.com/davlgd/gnap/blob/main/apps/conformance-web/README.md) is a web page over these checks, and the API documentation is on [docs.rs](https://docs.rs/gnap-conformance).

## Verify

```bash
cargo test -p gnap-conformance --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
