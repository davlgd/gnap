/** Grant request validation -- RFC 9635 Section 2 */

import type { GrantRequest } from "../types/grant.ts";
import type { AccessTokenRequestField, AccessTokenRequest } from "../types/token.ts";
import type { ClientInstance, ClientInstanceInfo } from "../types/client.ts";
import type { Key, KeyRef } from "../types/key.ts";
import { isMultipleTokenRequest } from "../types/token.ts";
import { isInlineClient } from "../types/client.ts";
import { isInlineKey } from "../types/key.ts";

function checkLabelsUnique(
  labels: (string | undefined)[],
  section: string,
): string | null {
  const seen = new Set<string>();
  for (const label of labels) {
    if (label !== undefined) {
      if (seen.has(label)) {
        return `Duplicate label "${label}" (${section})`;
      }
      seen.add(label);
    }
  }
  return null;
}

function validateAccessTokenRequest(
  field: AccessTokenRequestField,
  errors: string[],
): void {
  if (isMultipleTokenRequest(field)) {
    if (field.length === 0) {
      errors.push("access_token array must not be empty (Section 2.1)");
    }
    for (let i = 0; i < field.length; i++) {
      const req = field[i]!;
      if (req.access.length === 0) {
        errors.push(`access_token[${i}].access must not be empty (Section 2.1)`);
      }
      if (req.label === undefined) {
        errors.push(`access_token[${i}].label is required for multi-token requests (Section 2.1)`);
      }
    }
    const dup = checkLabelsUnique(
      field.map((r) => r.label),
      "Section 2.1",
    );
    if (dup) errors.push(dup);
  } else {
    if (field.access.length === 0) {
      errors.push("access_token.access must not be empty (Section 2.1)");
    }
  }
}

function validateClientInstance(
  client: ClientInstance,
  errors: string[],
): void {
  if (!isInlineClient(client)) {
    if (client === "") {
      errors.push("client reference must not be empty (Section 2.3)");
    }
    return;
  }

  const info = client as ClientInstanceInfo;
  if (isInlineKey(info.key)) {
    const k = info.key as Key;
    if (!k.jwk && !k.cert && !k["cert#S256"]) {
      errors.push("client key must contain jwk, cert, or cert#S256 (Section 7.1)");
    }
  } else {
    if ((info.key as string) === "") {
      errors.push("client key reference must not be empty (Section 7.1)");
    }
  }
}

/** Validate a grant request for RFC 9635 compliance. Returns an array of error messages. */
export function validateGrantRequest(req: GrantRequest): string[] {
  const errors: string[] = [];

  if (req.access_token !== undefined) {
    validateAccessTokenRequest(req.access_token, errors);
  }

  validateClientInstance(req.client, errors);

  if (req.interact) {
    if (req.interact.start.length === 0 && !req.interact.finish) {
      errors.push("interact must have start modes or a finish method (Section 2.5)");
    }
    if (req.interact.finish) {
      const fin = req.interact.finish;
      if (fin.nonce === "") {
        errors.push("interact.finish.nonce must not be empty (Section 2.5.2)");
      }
      if (fin.uri === "") {
        errors.push("interact.finish.uri must not be empty (Section 2.5.2)");
      }
      if (fin.method !== "redirect" && fin.method !== "push") {
        errors.push(
          `interact.finish.method must be "redirect" or "push", got "${fin.method}" (Section 2.5.2)`,
        );
      }
    }
  }

  return errors;
}
