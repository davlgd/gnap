/** JWK (JSON Web Key) utilities -- RFC 7517, used by RFC 9635 Section 7.1 */

import { GnapComplianceError } from "../types/error.ts";

/** An Ed25519 JSON Web Key for GNAP. */
export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  alg: "EdDSA";
  x: string;
  kid?: string;
  use?: string;
  d?: string;
}

/** Generate a new Ed25519 key pair using Web Crypto. */
export async function generateEd25519Key(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
}

/** Export the public part of an Ed25519 CryptoKey as a GNAP-compliant JWK. */
export async function exportPublicJwk(
  key: CryptoKey,
  kid?: string,
): Promise<Ed25519Jwk> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return {
    kty: "OKP",
    crv: "Ed25519",
    alg: "EdDSA",
    x: jwk.x!,
    kid,
    use: "sig",
  };
}

/** Export an Ed25519 CryptoKey pair as a GNAP JWK (public only). */
export async function exportKeyPairJwk(
  keyPair: CryptoKeyPair,
  kid?: string,
): Promise<Ed25519Jwk> {
  return exportPublicJwk(keyPair.publicKey, kid);
}

/** Import an Ed25519 JWK as a CryptoKey for verification. */
export async function importPublicJwk(jwk: Ed25519Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    "Ed25519",
    true,
    ["verify"],
  );
}

/** Import an Ed25519 JWK with private key (d field) as a CryptoKey for signing. */
export async function importPrivateJwk(jwk: Ed25519Jwk & { d: string }): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d },
    "Ed25519",
    true,
    ["sign"],
  );
}

/**
 * Validate a JWK structure for GNAP compliance.
 * RFC 9635 Section 7.1: A JWK MUST contain alg and kid. alg MUST NOT be "none".
 */
export function validateEd25519Jwk(jwk: Ed25519Jwk): void {
  if (jwk.kty !== "OKP") {
    throw GnapComplianceError.validation(
      `Expected kty="OKP", got "${jwk.kty}"`,
    );
  }
  if (jwk.crv !== "Ed25519") {
    throw GnapComplianceError.validation(
      `Expected crv="Ed25519", got "${jwk.crv}"`,
    );
  }
  if (!jwk.x) {
    throw GnapComplianceError.validation("JWK x field must not be empty");
  }
  if (jwk.alg === ("none" as string)) {
    throw GnapComplianceError.validation(
      'JWK alg must not be "none" (Section 7.1)',
    );
  }
  if (jwk.alg !== "EdDSA") {
    throw GnapComplianceError.validation(
      `Expected alg="EdDSA" for OKP/Ed25519, got "${jwk.alg}"`,
    );
  }
  if (!jwk.kid) {
    throw GnapComplianceError.validation(
      "JWK kid is required for GNAP (Section 7.1)",
    );
  }
}

/** Serialize a JWK as a JWKS (JSON Web Key Set). */
export function toJwks(jwk: Ed25519Jwk): { keys: Ed25519Jwk[] } {
  return { keys: [jwk] };
}
