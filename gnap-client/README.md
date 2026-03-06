# gnap-client

A TypeScript client for the [GNAP protocol](https://www.rfc-editor.org/rfc/rfc9635) (Grant Negotiation and Authorization Protocol), built on [Bun](https://bun.sh). Zero runtime dependencies.

Use it to test a GNAP Authorization Server, integrate the protocol into your application, or demonstrate its capabilities to technical stakeholders.

## Quick start

```bash
bun install
```

### Interactive web demo

A self-contained demo with embedded mock AS, dark UI, and 11 protocol scenarios:

```bash
bun run demo:web
```

Open `http://localhost:3000` (override with `GNAP_PORT=8080`).

### CLI demo

```bash
bun run demo
```

### Use as a library

```ts
import { GnapClient } from "gnap-client";

const client = new GnapClient({
  grantEndpoint: "https://as.example.com/gnap",
  displayName: "My App",
});
await client.init();

const response = await client.requestGrant({
  access_token: {
    access: [{ type: "api", actions: ["read"] }],
  },
  interact: {
    start: ["redirect"],
    finish: {
      method: "redirect",
      uri: "https://myapp.example.com/callback",
      nonce: crypto.randomUUID(),
    },
  },
});

// After user interaction:
const grant = await client.continueGrant(interactRef);
const token = client.getAccessToken();
```

## Features

**RFC 9635 -- Core Protocol**

- Grant requests (single and multiple access tokens)
- All interaction modes: `redirect`, `app`, `user_code`, `user_code_uri`
- Continuation API: polling, modification, revocation
- Token management: rotation, revocation
- Subject information requests
- Interaction hash validation (`sha-256`, `sha-512`)

**RFC 9767 -- Resource Server Connections**

- AS discovery (`.well-known/gnap-as-rs`)
- Token introspection

**Crypto (zero dependencies)**

- Ed25519 key generation and JWK export (Web Crypto API)
- HTTP Message Signatures (RFC 9421, `httpsig` proof method)
- Content-Digest (`sha-256`)

**Validation**

- Grant request and response validators matching RFC compliance rules
- 83 tests covering serialization, crypto, and protocol conformance

## Scripts

| Command | Description |
|---|---|
| `bun test` | Run the test suite |
| `bun run typecheck` | TypeScript type checking |
| `bun run demo` | CLI demo |
| `bun run demo:web` | Web demo with UI |
| `bun run demo:server` | Standalone mock AS |

## License

[Apache-2.0](../LICENSE)
