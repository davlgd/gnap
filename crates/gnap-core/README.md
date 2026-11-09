# gnap-core

The GNAP grant-state machine: transitions, guards and response constraints without HTTP, cryptography or storage I/O.

## Apply a transition

```rust
use gnap_core::{Event, Grant, State};

let mut grant = Grant::new();
assert_eq!(grant.state(), State::Processing);
grant.apply(Event::AsRequiresInteraction, 0).unwrap();
assert_eq!(grant.state(), State::Pending);
assert!(!grant.allowed().access_token);
```

Pass timestamps explicitly so the caller controls time in both applications and tests. Use `check_response` to check the response constraints associated with a grant state. The authorization server combines these rules with policy, proofs, and storage.

## Verify the model

```bash
cargo test -p gnap-core --locked
```

The package includes the state-machine test fixture. It is a copy of the [repository model](https://github.com/davlgd/gnap/blob/main/vectors/state-machine.json), checked for consistency in CI. Finite sequence tests exercise that model; they don't establish every possible protocol history.

See [architecture](https://github.com/davlgd/gnap/blob/main/docs/architecture.md) for its place in a complete application.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
