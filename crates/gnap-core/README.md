# gnap-core

The GNAP grant-state machine: transitions, guards and response constraints
without HTTP, cryptography or storage I/O.

## Apply a transition

```rust
use gnap_core::{Event, Grant, State};

let mut grant = Grant::new();
assert_eq!(grant.state(), State::Processing);
grant.apply(Event::AsRequiresInteraction, 0).unwrap();
assert_eq!(grant.state(), State::Pending);
assert!(!grant.allowed().access_token);
```

Pass timestamps explicitly so the caller controls time in both applications
and tests. Use `check_response` to check the response constraints associated
with a grant state. The authorization server combines these rules with policy,
proof verification and transactional storage.

## Verify the model

```sh
cargo test -p gnap-core --locked
```

The package includes the state-machine test fixture. It is a copy of the
[repository model](https://github.com/davlgd/gnap/blob/main/vectors/state-machine.json),
checked for consistency in CI. Finite sequence tests exercise that model;
they do not establish every possible protocol history.

See [architecture](https://github.com/davlgd/gnap/blob/main/docs/architecture.md)
for its place in a complete application.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.85 or newer; Apache-2.0.
For source dependencies and the upcoming 0.1.0 publication, see the
[release guide](https://github.com/davlgd/gnap/blob/main/docs/releasing.md).
