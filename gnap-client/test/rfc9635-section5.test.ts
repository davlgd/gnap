/** Continuation tests -- RFC 9635 Section 5 */
import { describe, test, expect } from "bun:test";
import type { ContinueRequest, ContinueResponse } from "../src/types/token.ts";
import { CONTINUE_REQUEST } from "./fixtures.ts";

describe("RFC 9635 Section 5 -- Continuation", () => {
  test("parse continue request", () => {
    const req = JSON.parse(CONTINUE_REQUEST) as ContinueRequest;
    expect(req.interact_ref).toBe("4IFWWIKYBC2PQ6U56NL1");
  });

  test("parse polling continue request", () => {
    const req = JSON.parse("{}") as ContinueRequest;
    expect(req.interact_ref).toBeUndefined();
  });

  test("roundtrip continue request", () => {
    const parsed = JSON.parse(CONTINUE_REQUEST) as ContinueRequest;
    const reserialized = JSON.stringify(parsed);
    const reparsed = JSON.parse(reserialized) as ContinueRequest;
    expect(reparsed).toEqual(parsed);
  });

  test("roundtrip polling continue request", () => {
    const parsed = JSON.parse("{}") as ContinueRequest;
    const reserialized = JSON.stringify(parsed);
    const reparsed = JSON.parse(reserialized) as ContinueRequest;
    expect(reparsed).toEqual(parsed);
  });

  test("continue response with wait", () => {
    const resp: ContinueResponse = {
      access_token: { value: "cont-tok" },
      uri: "https://as.example.com/continue/123",
      wait: 30,
    };
    const json = JSON.stringify(resp);
    const parsed = JSON.parse(json) as ContinueResponse;
    expect(parsed.wait).toBe(30);
  });

  test("continue response wait is optional", () => {
    const resp: ContinueResponse = {
      access_token: { value: "cont-tok" },
      uri: "https://as.example.com/continue/123",
    };
    const json = JSON.stringify(resp);
    const parsed = JSON.parse(json) as ContinueResponse;
    expect(parsed.wait).toBeUndefined();
  });
});
