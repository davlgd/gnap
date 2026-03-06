/** Key and proofing types -- RFC 9635 Section 7.1 */

/**
 * Proof method for demonstrating possession of a key.
 * RFC 9635 Section 7.3: either a string ("httpsig", "mtls", "jwsd", "jws")
 * or an object with a method field.
 */
export type ProofMethod = string | { method: string };

export function getProofMethodName(proof: ProofMethod): string {
  return typeof proof === "string" ? proof : proof.method;
}

/** A key used by a client instance or bound to an access token. RFC 9635 Section 7.1 */
export interface Key {
  proof: ProofMethod;
  jwk?: JsonWebKey;
  cert?: string;
  "cert#S256"?: string;
}

/**
 * A key reference or inline key.
 * Used in client instance and access token key fields.
 * RFC 9635 Section 7.1
 */
export type KeyRef = Key | string;

export function isInlineKey(ref: KeyRef): ref is Key {
  return typeof ref === "object" && "proof" in ref;
}
