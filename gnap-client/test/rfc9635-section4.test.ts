/** Interaction Hash tests -- RFC 9635 Section 4 */
import { describe, test, expect } from "bun:test";
import {
  computeInteractionHash,
  parseHashMethod,
} from "../src/crypto/hash.ts";

describe("RFC 9635 Section 4 -- Interaction Hash", () => {
  test("interaction hash sha256 basic", async () => {
    const hash = await computeInteractionHash(
      "client-nonce-1",
      "server-nonce-1",
      "interact-ref-1",
      "https://as.example.com/gnap",
    );
    expect(hash).toBeTruthy();
    // base64url: no padding, no + or /
    expect(hash).not.toContain("=");
    expect(hash).not.toContain("+");
    expect(hash).not.toContain("/");
  });

  test("interaction hash deterministic", async () => {
    const args = [
      "client-nonce-1",
      "server-nonce-1",
      "interact-ref-1",
      "https://as.example.com/gnap",
    ] as const;
    const hash1 = await computeInteractionHash(...args);
    const hash2 = await computeInteractionHash(...args);
    expect(hash1).toBe(hash2);
  });

  test("interaction hash changes with any input", async () => {
    const base = await computeInteractionHash(
      "nonce-a", "nonce-b", "ref-1", "https://as.example.com/gnap",
    );

    const changed1 = await computeInteractionHash(
      "nonce-X", "nonce-b", "ref-1", "https://as.example.com/gnap",
    );
    expect(changed1).not.toBe(base);

    const changed2 = await computeInteractionHash(
      "nonce-a", "nonce-X", "ref-1", "https://as.example.com/gnap",
    );
    expect(changed2).not.toBe(base);

    const changed3 = await computeInteractionHash(
      "nonce-a", "nonce-b", "ref-X", "https://as.example.com/gnap",
    );
    expect(changed3).not.toBe(base);

    const changed4 = await computeInteractionHash(
      "nonce-a", "nonce-b", "ref-1", "https://other.example.com/gnap",
    );
    expect(changed4).not.toBe(base);
  });

  test("interaction hash sha512 differs from sha256", async () => {
    const args = [
      "nonce-a", "nonce-b", "ref-1", "https://as.example.com/gnap",
    ] as const;
    const sha256 = await computeInteractionHash(...args, "sha-256");
    const sha512 = await computeInteractionHash(...args, "sha-512");
    expect(sha256).not.toBe(sha512);
    // SHA-512 produces longer output
    expect(sha512.length).toBeGreaterThan(sha256.length);
  });

  test("hash method parsing", () => {
    expect(parseHashMethod("sha-256")).toBe("sha-256");
    expect(parseHashMethod("sha-512")).toBe("sha-512");
    expect(parseHashMethod("sha256")).toBeNull();
    expect(parseHashMethod("sha512")).toBeNull();
    expect(parseHashMethod("md5")).toBeNull();
  });
});
