/** HTTP Message Signatures helpers -- RFC 9421, used by RFC 9635 Section 7.3.1 */

import { GnapComplianceError } from "../types/error.ts";

const encoder = new TextEncoder();

/** Components covered by GNAP HTTP signatures. */
export const GNAP_SIGNATURE_COMPONENTS = [
  "@method",
  "@target-uri",
  "content-type",
  "content-digest",
  "content-length",
  "authorization",
] as const;

/**
 * Build the signature base string per RFC 9421 Section 2.5.
 * Each component is formatted as `"component": value`, followed by @signature-params.
 */
export function buildSignatureBase(
  components: [name: string, value: string][],
  sigParams: string,
): string {
  const parts = components.map(([name, value]) => `"${name}": ${value}`);
  parts.push(`"@signature-params": ${sigParams}`);
  return parts.join("\n");
}

/**
 * Build the signature parameters string per RFC 9421 Section 2.3.
 * Format: `("c1" "c2");created=TIMESTAMP;keyid="KEY_ID";tag="gnap"`
 * RFC 9635 Section 7.3.1: tag="gnap" is REQUIRED.
 */
export function buildSignatureParams(
  componentNames: string[],
  created: number,
  keyId: string,
): string {
  const names = componentNames.map((n) => `"${n}"`).join(" ");
  return `(${names});created=${created};keyid="${keyId}";tag="gnap"`;
}

/** Sign a signature base string with an Ed25519 CryptoKey. Returns base64-encoded signature. */
export async function signEd25519(
  privateKey: CryptoKey,
  signatureBase: string,
): Promise<string> {
  const data = encoder.encode(signatureBase);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, data);
  return Buffer.from(signature).toString("base64");
}

/** Verify an Ed25519 signature against a signature base string. */
export async function verifyEd25519(
  publicKey: CryptoKey,
  signatureBase: string,
  signatureB64: string,
): Promise<void> {
  const sigBytes = Buffer.from(signatureB64, "base64");
  if (sigBytes.length !== 64) {
    throw GnapComplianceError.crypto(
      "Invalid signature length (expected 64 bytes)",
    );
  }

  const data = encoder.encode(signatureBase);
  const valid = await crypto.subtle.verify("Ed25519", publicKey, sigBytes, data);
  if (!valid) {
    throw GnapComplianceError.crypto("Signature verification failed");
  }
}

/**
 * Full sign-and-produce-headers workflow for GNAP HTTP requests.
 * Returns `{ signature, signatureInput }` ready for HTTP headers.
 */
export async function createGnapSignatureHeaders(
  privateKey: CryptoKey,
  keyId: string,
  components: [name: string, value: string][],
  created: number,
): Promise<{ signature: string; signatureInput: string }> {
  const componentNames = components.map(([name]) => name);
  const sigParams = buildSignatureParams(componentNames, created, keyId);
  const sigBase = buildSignatureBase(components, sigParams);
  const sig = await signEd25519(privateKey, sigBase);
  return {
    signature: `sig1=:${sig}:`,
    signatureInput: `sig1=${sigParams}`,
  };
}

export interface ParsedSignatureInput {
  components: string[];
  created: number;
  keyId: string;
}

/**
 * Parse a `Signature-Input` header value to extract components, created, and keyid.
 * Expects: `sig1=("c1" "c2");created=TIMESTAMP;keyid="KEY_ID";tag="gnap"`
 * RFC 9635 Section 7.3.1: verifier MUST verify tag="gnap" is present.
 */
export function parseSignatureInput(input: string): ParsedSignatureInput {
  const stripped = input.startsWith("sig1=") ? input.slice(5) : input;

  let components: string[] = [];
  let created: number | undefined;
  let keyId: string | undefined;
  let tag: string | undefined;

  for (const part of stripped.split(";")) {
    const trimmed = part.trim();

    if (trimmed.startsWith("(")) {
      const inner = trimmed.slice(1, -1);
      components = inner
        .split(/\s+/)
        .filter(Boolean)
        .map((s) => s.replace(/"/g, ""));
    } else if (trimmed.startsWith("created=")) {
      const val = parseInt(trimmed.slice(8), 10);
      if (Number.isNaN(val)) {
        throw GnapComplianceError.validation("Invalid created timestamp");
      }
      created = val;
    } else if (trimmed.startsWith("keyid=")) {
      keyId = trimmed.slice(6).replace(/"/g, "");
    } else if (trimmed.startsWith("tag=")) {
      tag = trimmed.slice(4).replace(/"/g, "");
    } else if (trimmed.startsWith("alg=")) {
      throw GnapComplianceError.validation(
        "alg parameter MUST NOT be included in GNAP signatures (Section 7.3.1)",
      );
    }
  }

  if (created === undefined) {
    throw GnapComplianceError.validation(
      "Missing created in Signature-Input",
    );
  }
  if (keyId === undefined) {
    throw GnapComplianceError.validation(
      "Missing keyid in Signature-Input",
    );
  }
  if (tag !== "gnap") {
    throw GnapComplianceError.validation(
      tag === undefined
        ? 'Missing tag="gnap" in Signature-Input (Section 7.3.1)'
        : `tag must be "gnap", got "${tag}" (Section 7.3.1)`,
    );
  }

  return { components, created, keyId };
}
