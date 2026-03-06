/** Grant Response tests -- RFC 9635 Section 3 */
import { describe, test, expect } from "bun:test";
import type { GrantResponse } from "../src/types/grant.ts";
import type { AccessToken } from "../src/types/token.ts";
import { isMultipleTokenResponse } from "../src/types/token.ts";
import { validateGrantResponse } from "../src/validation/grant-response.ts";
import {
  GRANT_RESPONSE_WITH_TOKEN,
  GRANT_RESPONSE_WITH_INTERACTION,
  GRANT_RESPONSE_MULTIPLE_TOKENS,
  GRANT_RESPONSE_USER_CODE,
  GRANT_RESPONSE_USER_CODE_URI,
} from "./fixtures.ts";

function roundtrip<T>(json: string): T {
  const parsed = JSON.parse(json) as T;
  const reserialized = JSON.stringify(parsed);
  const reparsed = JSON.parse(reserialized) as T;
  expect(reparsed).toEqual(parsed);
  return parsed;
}

describe("RFC 9635 Section 3 -- Grant Response", () => {
  test("parse response with token", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_TOKEN) as GrantResponse;
    expect(resp.continue).toBeDefined();
    expect(resp.continue!.access_token.value).toBe("80UPRY5NM33OMUKMKSKU");
    expect(resp.continue!.uri).toBe("https://server.example.com/continue/VGJKPTKC50");

    expect(resp.access_token).toBeDefined();
    const token = resp.access_token as AccessToken;
    expect(token.value).toBe("OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0");
    expect(token.manage).toBeDefined();
    expect(token.manage!.uri).toBe("https://server.example.com/token/PRY5NM33O");
    expect(token.access).toHaveLength(1);
  });

  test("parse response with interaction", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_INTERACTION) as GrantResponse;
    expect(resp.interact).toBeDefined();
    expect(resp.interact!.redirect).toBe(
      "https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ",
    );
    expect(resp.interact!.finish).toBe("MBDOFXG4Y5CVJCX821LH");
    expect(resp.continue!.wait).toBe(30);
  });

  test("parse response with multiple tokens", () => {
    const resp = JSON.parse(GRANT_RESPONSE_MULTIPLE_TOKENS) as GrantResponse;
    expect(isMultipleTokenResponse(resp.access_token!)).toBe(true);
    const tokens = resp.access_token as AccessToken[];
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.label).toBe("token1");
    expect(tokens[1]!.label).toBe("token2");
  });

  test("parse response with user_code", () => {
    const resp = JSON.parse(GRANT_RESPONSE_USER_CODE) as GrantResponse;
    expect(resp.interact!.user_code).toBe("A1BC-3DFF");
  });

  test("parse response with user_code_uri", () => {
    const resp = JSON.parse(GRANT_RESPONSE_USER_CODE_URI) as GrantResponse;
    expect(resp.interact!.user_code_uri).toBeDefined();
    expect(resp.interact!.user_code_uri!.code).toBe("A1BC-3DFF");
    expect(resp.interact!.user_code_uri!.uri).toBe("https://server.example.com/device");
  });

  test("roundtrip response with token", () => {
    roundtrip<GrantResponse>(GRANT_RESPONSE_WITH_TOKEN);
  });

  test("roundtrip response with interaction", () => {
    roundtrip<GrantResponse>(GRANT_RESPONSE_WITH_INTERACTION);
  });

  test("roundtrip response with multiple tokens", () => {
    roundtrip<GrantResponse>(GRANT_RESPONSE_MULTIPLE_TOKENS);
  });

  test("validate valid response with token", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_TOKEN) as GrantResponse;
    expect(validateGrantResponse(resp)).toEqual([]);
  });

  test("validate valid response with interaction", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_INTERACTION) as GrantResponse;
    expect(validateGrantResponse(resp)).toEqual([]);
  });

  test("validate rejects empty response", () => {
    const resp: GrantResponse = {};
    const errors = validateGrantResponse(resp);
    expect(errors.length).toBeGreaterThan(0);
  });

  test("validate rejects empty token value", () => {
    const resp: GrantResponse = {
      access_token: { value: "", access: ["read"] },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("value"))).toBe(true);
  });

  test("validate rejects empty continue uri", () => {
    const resp: GrantResponse = {
      continue: { access_token: { value: "tok" }, uri: "" },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("uri"))).toBe(true);
  });

  test("validate rejects bearer with key", () => {
    const resp: GrantResponse = {
      access_token: {
        value: "tok",
        access: ["read"],
        flags: ["bearer"],
        key: "some-key-ref",
      },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("bearer"))).toBe(true);
  });

  test("validate rejects duplicate flags", () => {
    const resp: GrantResponse = {
      access_token: {
        value: "tok",
        access: ["read"],
        flags: ["bearer", "bearer"],
      },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("duplicate flag"))).toBe(true);
  });

  test("validate rejects manage token same value", () => {
    const resp: GrantResponse = {
      access_token: {
        value: "same-value",
        access: ["read"],
        manage: {
          uri: "https://example.com/manage",
          access_token: { value: "same-value" },
        },
      },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("manage"))).toBe(true);
  });
});
