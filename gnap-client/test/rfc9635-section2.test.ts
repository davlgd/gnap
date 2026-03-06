/** Grant Request tests -- RFC 9635 Section 2 */
import { describe, test, expect } from "bun:test";
import type { GrantRequest } from "../src/types/grant.ts";
import type { AccessTokenRequest } from "../src/types/token.ts";
import { isExtendedStartMode } from "../src/types/interaction.ts";
import { isInlineClient } from "../src/types/client.ts";
import { isInlineKey } from "../src/types/key.ts";
import { isStructuredAccessRight } from "../src/types/resource.ts";
import { isMultipleTokenRequest } from "../src/types/token.ts";
import { validateGrantRequest } from "../src/validation/grant-request.ts";
import {
  GRANT_REQUEST_SINGLE_TOKEN,
  GRANT_REQUEST_MULTIPLE_TOKENS,
  GRANT_REQUEST_WITH_INTERACTION,
  GRANT_REQUEST_WITH_SUBJECT,
} from "./fixtures.ts";

function roundtrip<T>(json: string): T {
  const parsed = JSON.parse(json) as T;
  const reserialized = JSON.stringify(parsed);
  const reparsed = JSON.parse(reserialized) as T;
  expect(reparsed).toEqual(parsed);
  return parsed;
}

describe("RFC 9635 Section 2 -- Grant Request", () => {
  test("parse single token grant request", () => {
    const req = JSON.parse(GRANT_REQUEST_SINGLE_TOKEN) as GrantRequest;
    expect(req.access_token).toBeDefined();
    expect(isMultipleTokenRequest(req.access_token!)).toBe(false);

    const token = req.access_token as AccessTokenRequest;
    expect(token.access).toHaveLength(1);
    const right = token.access[0]!;
    expect(isStructuredAccessRight(right)).toBe(true);
    if (isStructuredAccessRight(right)) {
      expect(right.type).toBe("photo-api");
      expect(right.actions).toEqual(["read", "write", "delete"]);
    }

    expect(isInlineClient(req.client)).toBe(true);
    if (isInlineClient(req.client)) {
      expect(isInlineKey(req.client.key)).toBe(true);
    }
  });

  test("parse multiple token grant request", () => {
    const req = JSON.parse(GRANT_REQUEST_MULTIPLE_TOKENS) as GrantRequest;
    expect(isMultipleTokenRequest(req.access_token!)).toBe(true);

    const tokens = req.access_token as AccessTokenRequest[];
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.label).toBe("token1");
    expect(tokens[1]!.label).toBe("token2");

    expect(isInlineClient(req.client)).toBe(false);
    expect(req.client).toBe("client-instance-id-12345");
  });

  test("parse grant request with interaction", () => {
    const req = JSON.parse(GRANT_REQUEST_WITH_INTERACTION) as GrantRequest;
    expect(req.interact).toBeDefined();
    expect(req.interact!.start).toEqual(["redirect"]);
    expect(req.interact!.finish).toBeDefined();
    expect(req.interact!.finish!.method).toBe("redirect");
    expect(req.interact!.finish!.uri).toBe("https://client.example.net/return/123455");
    expect(req.interact!.finish!.nonce).toBe("LKLTI25DK82FX4T4QFZC");

    if (isInlineClient(req.client)) {
      expect(req.client.display).toBeDefined();
      expect(req.client.display!.name).toBe("My Client Display Name");
    }
  });

  test("parse grant request with subject", () => {
    const req = JSON.parse(GRANT_REQUEST_WITH_SUBJECT) as GrantRequest;
    expect(req.subject).toBeDefined();
    expect(req.subject!.sub_id_formats).toEqual(["opaque", "iss_sub"]);
    expect(req.subject!.assertion_formats).toEqual(["id_token"]);
  });

  test("parse extended start mode", () => {
    const json = `{
      "access_token": { "access": ["read"] },
      "client": "c1",
      "interact": {
        "start": [
          "redirect",
          { "mode": "custom-mode", "custom_param": "value" }
        ]
      }
    }`;
    const req = JSON.parse(json) as GrantRequest;
    expect(req.interact!.start).toHaveLength(2);
    const ext = req.interact!.start[1]!;
    expect(isExtendedStartMode(ext)).toBe(true);
    if (isExtendedStartMode(ext)) {
      expect(ext.mode).toBe("custom-mode");
      expect(ext.custom_param).toBe("value");
    }
  });

  test("roundtrip single token request", () => {
    roundtrip<GrantRequest>(GRANT_REQUEST_SINGLE_TOKEN);
  });

  test("roundtrip multiple token request", () => {
    roundtrip<GrantRequest>(GRANT_REQUEST_MULTIPLE_TOKENS);
  });

  test("roundtrip interaction request", () => {
    roundtrip<GrantRequest>(GRANT_REQUEST_WITH_INTERACTION);
  });

  test("validate valid single token request", () => {
    const req = JSON.parse(GRANT_REQUEST_SINGLE_TOKEN) as GrantRequest;
    expect(validateGrantRequest(req)).toEqual([]);
  });

  test("validate valid multiple token request", () => {
    const req = JSON.parse(GRANT_REQUEST_MULTIPLE_TOKENS) as GrantRequest;
    expect(validateGrantRequest(req)).toEqual([]);
  });

  test("validate rejects empty access", () => {
    const req: GrantRequest = {
      access_token: { access: [] },
      client: "c1",
    };
    const errors = validateGrantRequest(req);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.includes("access"))).toBe(true);
  });

  test("validate rejects multi-token without labels", () => {
    const req: GrantRequest = {
      access_token: [
        { access: ["read"] },
        { access: ["write"] },
      ],
      client: "c1",
    };
    const errors = validateGrantRequest(req);
    expect(errors.some((e) => e.includes("label"))).toBe(true);
  });

  test("validate rejects interact with no start and no finish", () => {
    const req: GrantRequest = {
      access_token: { access: ["read"] },
      client: "c1",
      interact: { start: [] },
    };
    const errors = validateGrantRequest(req);
    expect(errors.some((e) => e.includes("start modes or a finish"))).toBe(true);
  });

  test("validate accepts empty start with push finish", () => {
    const req: GrantRequest = {
      access_token: { access: ["read"] },
      client: "c1",
      interact: {
        start: [],
        finish: {
          method: "push",
          uri: "https://example.com/push",
          nonce: "abc",
        },
      },
    };
    expect(validateGrantRequest(req)).toEqual([]);
  });

  test("validate rejects invalid finish method", () => {
    const req: GrantRequest = {
      access_token: { access: ["read"] },
      client: "c1",
      interact: {
        start: ["redirect"],
        finish: {
          method: "invalid",
          uri: "https://example.com",
          nonce: "abc",
        },
      },
    };
    const errors = validateGrantRequest(req);
    expect(errors.some((e) => e.includes("method"))).toBe(true);
  });
});
