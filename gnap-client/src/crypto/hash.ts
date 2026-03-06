/** Interaction hash and content digest -- RFC 9635 Section 4.2.3, RFC 9530 */

const encoder = new TextEncoder();

export type HashMethod = "sha-256" | "sha-512";

const HASH_ALGO_MAP: Record<HashMethod, string> = {
  "sha-256": "SHA-256",
  "sha-512": "SHA-512",
};

/**
 * Compute the interaction hash for finish callback verification.
 *
 * hash = BASE64URL(HASH(client_nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + grant_endpoint))
 *
 * RFC 9635 Section 4.2.3
 */
export async function computeInteractionHash(
  clientNonce: string,
  serverNonce: string,
  interactRef: string,
  grantEndpoint: string,
  hashMethod: HashMethod = "sha-256",
): Promise<string> {
  const input = `${clientNonce}\n${serverNonce}\n${interactRef}\n${grantEndpoint}`;
  const algo = HASH_ALGO_MAP[hashMethod];
  if (!algo) throw new Error(`Unsupported hash method: ${hashMethod}`);

  const digest = await crypto.subtle.digest(algo, encoder.encode(input));
  return Buffer.from(digest).toString("base64url");
}

export function parseHashMethod(s: string): HashMethod | null {
  if (s === "sha-256" || s === "sha-512") return s;
  return null;
}

export type DigestAlgorithm = "sha-256" | "sha-512";

/**
 * Compute a content digest for HTTP request bodies.
 * Returns the digest in format: `sha-256=:BASE64(digest):` per RFC 9530.
 */
export async function computeContentDigest(
  body: Uint8Array,
  algorithm: DigestAlgorithm = "sha-256",
): Promise<string> {
  const algo = HASH_ALGO_MAP[algorithm];
  if (!algo) throw new Error(`Unsupported digest algorithm: ${algorithm}`);

  const digest = await crypto.subtle.digest(algo, new Uint8Array(body));
  const encoded = Buffer.from(digest).toString("base64");
  return `${algorithm}=:${encoded}:`;
}

export async function computeContentDigestSha256(body: Uint8Array): Promise<string> {
  return computeContentDigest(body, "sha-256");
}

export async function computeContentDigestSha512(body: Uint8Array): Promise<string> {
  return computeContentDigest(body, "sha-512");
}

/**
 * Verify a Content-Digest header value against a body.
 * RFC 9635 Section 7.3.1: the verifier MUST validate this field value.
 */
export async function verifyContentDigest(
  headerValue: string,
  body: Uint8Array,
): Promise<boolean> {
  const sepIdx = headerValue.indexOf("=:");
  if (sepIdx === -1) return false;

  const algorithm = headerValue.slice(0, sepIdx) as DigestAlgorithm;
  if (algorithm !== "sha-256" && algorithm !== "sha-512") return false;

  const expected = await computeContentDigest(body, algorithm);
  return headerValue === expected;
}
