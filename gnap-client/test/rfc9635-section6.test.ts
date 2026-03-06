/** Token Management tests -- RFC 9635 Section 6 */
import { describe, test, expect } from "bun:test";
import type { AccessToken, TokenRotationResponse } from "../src/types/token.ts";

describe("RFC 9635 Section 6 -- Token Management", () => {
  test("parse token rotation response", () => {
    const json = `{
      "access_token": {
        "value": "NEW-TOKEN-VALUE",
        "manage": {
          "uri": "https://server.example.com/token/NEW",
          "access_token": { "value": "NEW-MANAGE-TOKEN" }
        },
        "access": [{ "type": "photo-api", "actions": ["read"] }],
        "expires_in": 7200
      }
    }`;
    const resp = JSON.parse(json) as TokenRotationResponse;
    expect(resp.access_token.value).toBe("NEW-TOKEN-VALUE");
    expect(resp.access_token.manage).toBeDefined();
    expect(resp.access_token.expires_in).toBe(7200);
  });

  test("roundtrip token rotation response", () => {
    const resp: TokenRotationResponse = {
      access_token: {
        value: "rotated-token",
        access: ["read"],
        manage: {
          uri: "https://example.com/manage",
          access_token: { value: "manage-tok" },
        },
      },
    };
    const json = JSON.stringify(resp);
    const parsed = JSON.parse(json) as TokenRotationResponse;
    expect(parsed).toEqual(resp);
  });

  test("access token with bearer flag", () => {
    const token: AccessToken = {
      value: "bearer-token",
      access: ["read"],
      flags: ["bearer"],
    };
    expect(token.flags).toContain("bearer");
    expect(token.key).toBeUndefined();
  });

  test("access token without key binds to client", () => {
    const token: AccessToken = {
      value: "bound-token",
      access: ["read"],
    };
    // No key and no bearer flag means bound to the client's presented key
    expect(token.key).toBeUndefined();
    expect(token.flags).toBeUndefined();
  });

  test("access token with specific key binding", () => {
    const token: AccessToken = {
      value: "key-bound-token",
      access: ["read"],
      key: {
        proof: "httpsig",
        jwk: { kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: "abc123" } as JsonWebKey,
      },
    };
    expect(token.key).toBeDefined();
    expect(typeof token.key).toBe("object");
  });
});
