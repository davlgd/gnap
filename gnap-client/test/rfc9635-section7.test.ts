/** HTTP Signatures & Proofing tests -- RFC 9635 Section 7 */
import { describe, test, expect } from "bun:test";
import {
  buildSignatureBase,
  buildSignatureParams,
  signEd25519,
  verifyEd25519,
  createGnapSignatureHeaders,
  parseSignatureInput,
} from "../src/crypto/httpsig.ts";
import {
  computeContentDigestSha256,
  computeContentDigestSha512,
  verifyContentDigest,
} from "../src/crypto/hash.ts";
import {
  generateEd25519Key,
  exportKeyPairJwk,
  importPublicJwk,
  validateEd25519Jwk,
  toJwks,
  type Ed25519Jwk,
} from "../src/crypto/jwk.ts";
import { GnapComplianceError } from "../src/types/error.ts";

const encoder = new TextEncoder();

async function generateTestKeyPair() {
  return crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
}

describe("RFC 9635 Section 7 -- HTTP Signatures & Proofing", () => {
  test("GNAP authorization header format", () => {
    const token = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0";
    const header = `GNAP ${token}`;
    expect(header).toBe("GNAP OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0");
  });

  test("signature creation and verification", async () => {
    const keyPair = await generateTestKeyPair();
    const components: [string, string][] = [
      ["@method", "POST"],
      ["@target-uri", "https://as.example.com/gnap"],
      ["content-type", "application/json"],
    ];
    const created = 1234567890;

    const { signature, signatureInput } = await createGnapSignatureHeaders(
      keyPair.privateKey,
      "test-key",
      components,
      created,
    );

    // Parse back
    const parsed = parseSignatureInput(signatureInput);
    expect(parsed.components).toEqual(["@method", "@target-uri", "content-type"]);
    expect(parsed.created).toBe(created);
    expect(parsed.keyId).toBe("test-key");

    // Rebuild and verify
    const sigParams = buildSignatureParams(parsed.components, parsed.created, parsed.keyId);
    const sigBase = buildSignatureBase(
      parsed.components.map((name, i) => [name, components[i]![1]]),
      sigParams,
    );

    const sigValue = signature.slice("sig1=:".length, -1);
    await verifyEd25519(keyPair.publicKey, sigBase, sigValue);
  });

  test("signature with authorization header", async () => {
    const keyPair = await generateTestKeyPair();
    const components: [string, string][] = [
      ["@method", "POST"],
      ["@target-uri", "https://as.example.com/continue"],
      ["authorization", "GNAP some-token"],
    ];

    const { signature } = await createGnapSignatureHeaders(
      keyPair.privateKey,
      "test-key",
      components,
      1234567890,
    );

    expect(signature).toMatch(/^sig1=:/);
  });

  test("signature components order matters", async () => {
    const keyPair = await generateTestKeyPair();

    const sig1 = await signEd25519(
      keyPair.privateKey,
      '"@method": POST\n"@target-uri": https://as.example.com',
    );
    const sig2 = await signEd25519(
      keyPair.privateKey,
      '"@target-uri": https://as.example.com\n"@method": POST',
    );

    expect(sig1).not.toBe(sig2);
  });

  test("verify rejects tampered base", async () => {
    const keyPair = await generateTestKeyPair();
    const sigBase = '"@method": POST\n"@target-uri": https://as.example.com/gnap';
    const sig = await signEd25519(keyPair.privateKey, sigBase);

    const tampered = '"@method": GET\n"@target-uri": https://as.example.com/gnap';
    await expect(verifyEd25519(keyPair.publicKey, tampered, sig)).rejects.toThrow();
  });

  test("verify rejects wrong key", async () => {
    const key1 = await generateTestKeyPair();
    const key2 = await generateTestKeyPair();
    const sig = await signEd25519(key1.privateKey, '"@method": POST');

    await expect(verifyEd25519(key2.publicKey, '"@method": POST', sig)).rejects.toThrow();
  });

  test("verify rejects invalid base64", async () => {
    const keyPair = await generateTestKeyPair();
    await expect(
      verifyEd25519(keyPair.publicKey, "test", "not-valid-base64!!!"),
    ).rejects.toThrow();
  });

  test("sign verify empty message", async () => {
    const keyPair = await generateTestKeyPair();
    const sig = await signEd25519(keyPair.privateKey, "");
    await verifyEd25519(keyPair.publicKey, "", sig);
  });

  test("sign verify unicode message", async () => {
    const keyPair = await generateTestKeyPair();
    const sig = await signEd25519(keyPair.privateKey, "Hello, World!");
    await verifyEd25519(keyPair.publicKey, "Hello, World!", sig);
  });

  test("parse signature input valid", () => {
    const input =
      'sig1=("@method" "@target-uri" "content-type");created=1618884473;keyid="gnap-key";tag="gnap"';
    const parsed = parseSignatureInput(input);
    expect(parsed.components).toEqual(["@method", "@target-uri", "content-type"]);
    expect(parsed.created).toBe(1618884473);
    expect(parsed.keyId).toBe("gnap-key");
  });

  test("parse signature input missing created", () => {
    const input = 'sig1=("@method");keyid="k";tag="gnap"';
    expect(() => parseSignatureInput(input)).toThrow();
  });

  test("parse signature input missing keyid", () => {
    const input = 'sig1=("@method");created=123;tag="gnap"';
    expect(() => parseSignatureInput(input)).toThrow();
  });

  test("parse signature input missing tag", () => {
    const input = 'sig1=("@method");created=123;keyid="k"';
    expect(() => parseSignatureInput(input)).toThrow();
  });

  test("parse signature input rejects wrong tag", () => {
    const input = 'sig1=("@method");created=123;keyid="k";tag="other"';
    expect(() => parseSignatureInput(input)).toThrow();
  });

  test("parse signature input rejects alg parameter", () => {
    const input = 'sig1=("@method");created=123;keyid="k";tag="gnap";alg="ed25519"';
    expect(() => parseSignatureInput(input)).toThrow(/alg/);
  });

  // Content Digest tests
  test("content digest sha256 deterministic", async () => {
    const body = encoder.encode("hello");
    const d1 = await computeContentDigestSha256(body);
    const d2 = await computeContentDigestSha256(body);
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^sha-256=:/);
    expect(d1).toMatch(/:$/);
  });

  test("content digest sha512 deterministic", async () => {
    const body = encoder.encode("hello");
    const d1 = await computeContentDigestSha512(body);
    const d2 = await computeContentDigestSha512(body);
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^sha-512=:/);
  });

  test("content digest changes with body", async () => {
    const d1 = await computeContentDigestSha256(encoder.encode("hello"));
    const d2 = await computeContentDigestSha256(encoder.encode("world"));
    expect(d1).not.toBe(d2);
  });

  test("verify content digest", async () => {
    const body = encoder.encode("test body");
    const digest = await computeContentDigestSha256(body);
    expect(await verifyContentDigest(digest, body)).toBe(true);
    expect(await verifyContentDigest(digest, encoder.encode("wrong"))).toBe(false);
  });

  // JWK tests
  test("jwk ed25519 roundtrip", async () => {
    const keyPair = await generateEd25519Key();
    const jwk = await exportKeyPairJwk(keyPair, "test-kid");

    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.alg).toBe("EdDSA");
    expect(jwk.kid).toBe("test-kid");
    expect(jwk.x).toBeTruthy();

    // Import back and verify
    const importedKey = await importPublicJwk(jwk);
    const message = encoder.encode("test message");
    const sig = await crypto.subtle.sign("Ed25519", keyPair.privateKey, message);
    const valid = await crypto.subtle.verify("Ed25519", importedKey, sig, message);
    expect(valid).toBe(true);
  });

  test("jwk validation requires okp kty", () => {
    expect(() =>
      validateEd25519Jwk({
        kty: "EC" as "OKP",
        crv: "Ed25519",
        alg: "EdDSA",
        x: "AAAA",
        kid: "k1",
      }),
    ).toThrow(/kty/);
  });

  test("jwk validation rejects empty x", () => {
    expect(() =>
      validateEd25519Jwk({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: "", kid: "k1" }),
    ).toThrow(/x field/);
  });

  test("jwk validation rejects missing kid", () => {
    expect(() =>
      validateEd25519Jwk({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: "AAAA" }),
    ).toThrow(/kid/);
  });

  test("jwk validation rejects alg none", () => {
    expect(() =>
      validateEd25519Jwk({
        kty: "OKP",
        crv: "Ed25519",
        alg: "none" as "EdDSA",
        x: "AAAA",
        kid: "k1",
      }),
    ).toThrow(/none/);
  });

  test("jwks serialization", async () => {
    const keyPair = await generateEd25519Key();
    const jwk = await exportKeyPairJwk(keyPair, "k1");
    const jwks = toJwks(jwk);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]!.kid).toBe("k1");
  });

  test("jwk from json", () => {
    const json = `{
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "x": "dGVzdC1rZXktdmFsdWUtMTIzNDU2Nzg5MGFi",
      "kid": "gnap-rfc-example",
      "use": "sig"
    }`;
    const jwk = JSON.parse(json) as Ed25519Jwk;
    expect(jwk.kty).toBe("OKP");
    expect(jwk.kid).toBe("gnap-rfc-example");
    expect(jwk.use).toBe("sig");
  });
});
