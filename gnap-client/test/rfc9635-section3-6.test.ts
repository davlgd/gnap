/** Error Response tests -- RFC 9635 Section 3.6 */
import { describe, test, expect } from "bun:test";
import type { GrantResponse } from "../src/types/grant.ts";
import {
  type GnapError,
  GnapErrorCode,
  isGnapErrorObject,
  getErrorCode,
} from "../src/types/error.ts";
import { validateGrantResponse } from "../src/validation/grant-response.ts";
import {
  ERROR_RESPONSE,
  ERROR_INVALID_REQUEST,
  GRANT_RESPONSE_WITH_ERROR,
  GRANT_RESPONSE_WITH_ERROR_CODE,
} from "./fixtures.ts";

describe("RFC 9635 Section 3.6 -- Error Responses", () => {
  test("parse user_denied error", () => {
    const err = JSON.parse(ERROR_RESPONSE) as GnapError;
    expect(err.code).toBe(GnapErrorCode.UserDenied);
    expect(err.description).toBe("The RO denied the request");
  });

  test("parse invalid_request error", () => {
    const err = JSON.parse(ERROR_INVALID_REQUEST) as GnapError;
    expect(err.code).toBe(GnapErrorCode.InvalidRequest);
    expect(err.description).toBeDefined();
  });

  test("roundtrip all error codes", () => {
    for (const code of Object.values(GnapErrorCode)) {
      const err: GnapError = { code };
      const json = JSON.stringify(err);
      const parsed = JSON.parse(json) as GnapError;
      expect(parsed.code).toBe(code);
    }
  });

  test("unknown error code preserved", () => {
    const json = `{"code": "custom_error", "description": "test"}`;
    const err = JSON.parse(json) as GnapError;
    expect(err.code).toBe("custom_error");
  });

  test("error without description", () => {
    const json = `{"code": "user_denied"}`;
    const err = JSON.parse(json) as GnapError;
    expect(err.code).toBe(GnapErrorCode.UserDenied);
    expect(err.description).toBeUndefined();
  });

  test("parse grant response with error object", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_ERROR) as GrantResponse;
    expect(resp.error).toBeDefined();
    expect(isGnapErrorObject(resp.error!)).toBe(true);
    if (isGnapErrorObject(resp.error!)) {
      expect(resp.error.code).toBe(GnapErrorCode.UserDenied);
    }
  });

  test("parse grant response with error code string", () => {
    const resp = JSON.parse(GRANT_RESPONSE_WITH_ERROR_CODE) as GrantResponse;
    expect(resp.error).toBeDefined();
    expect(isGnapErrorObject(resp.error!)).toBe(false);
    expect(getErrorCode(resp.error!)).toBe("user_denied");
  });

  test("roundtrip grant response with error", () => {
    const parsed = JSON.parse(GRANT_RESPONSE_WITH_ERROR) as GrantResponse;
    const reserialized = JSON.stringify(parsed);
    const reparsed = JSON.parse(reserialized) as GrantResponse;
    expect(reparsed).toEqual(parsed);
  });

  test("error must not coexist with access_token", () => {
    const resp: GrantResponse = {
      error: { code: "user_denied" },
      access_token: { value: "tok", access: ["read"] },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("error") && e.includes("Section 3.6"))).toBe(true);
  });

  test("error may coexist with continue", () => {
    const resp: GrantResponse = {
      error: { code: "user_denied" },
      continue: {
        access_token: { value: "cont-tok" },
        uri: "https://example.com/continue",
      },
    };
    const errors = validateGrantResponse(resp);
    expect(errors.some((e) => e.includes("Section 3.6"))).toBe(false);
  });
});
