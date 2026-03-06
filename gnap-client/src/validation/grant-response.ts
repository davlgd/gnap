/** Grant response validation -- RFC 9635 Section 3 */

import type { GrantResponse } from "../types/grant.ts";
import type { AccessTokenResponseField, AccessToken } from "../types/token.ts";
import { isMultipleTokenResponse } from "../types/token.ts";

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

function validateSingleToken(
  token: AccessToken,
  prefix: string,
  errors: string[],
): void {
  if (token.value === "") {
    errors.push(`${prefix}.value must not be empty (Section 3.2)`);
  }
  if (token.access.length === 0) {
    errors.push(`${prefix}.access must not be empty (Section 3.2.1)`);
  }
  if (token.flags) {
    if (token.flags.includes("bearer") && token.key !== undefined) {
      errors.push(
        `${prefix}: bearer flag and key must not both be present (Section 3.2.1)`,
      );
    }
    const seen = new Set<string>();
    for (const flag of token.flags) {
      if (seen.has(flag)) {
        errors.push(`${prefix}: duplicate flag "${flag}" (Section 3.2.1)`);
      }
      seen.add(flag);
    }
  }
  if (token.manage && token.manage.access_token.value === token.value) {
    errors.push(
      `${prefix}: manage.access_token.value must differ from token value (Section 3.2.1)`,
    );
  }
}

function validateAccessTokenResponse(
  field: AccessTokenResponseField,
  errors: string[],
): void {
  if (isMultipleTokenResponse(field)) {
    if (field.length === 0) {
      errors.push("access_token array must not be empty (Section 3.2)");
    }
    for (let i = 0; i < field.length; i++) {
      const token = field[i]!;
      validateSingleToken(token, `access_token[${i}]`, errors);
      if (token.label === undefined) {
        errors.push(
          `access_token[${i}].label is required for multi-token responses (Section 3.2)`,
        );
      }
    }
    const dup = checkLabelsUnique(
      field.map((t) => t.label),
      "Section 3.2",
    );
    if (dup) errors.push(dup);
  } else {
    validateSingleToken(field, "access_token", errors);
  }
}

/** Validate a grant response for RFC 9635 compliance. Returns an array of error messages. */
export function validateGrantResponse(resp: GrantResponse): string[] {
  const errors: string[] = [];

  if (
    !resp.continue &&
    !resp.access_token &&
    !resp.interact &&
    !resp.subject &&
    !resp.instance_id &&
    !resp.error
  ) {
    errors.push(
      "Grant response must contain at least one field (Section 3)",
    );
  }

  if (resp.continue) {
    if (resp.continue.access_token.value === "") {
      errors.push(
        "continue.access_token.value must not be empty (Section 3.1)",
      );
    }
    if (resp.continue.uri === "") {
      errors.push("continue.uri must not be empty (Section 3.1)");
    }
  }

  if (resp.access_token) {
    validateAccessTokenResponse(resp.access_token, errors);
  }

  if (
    resp.error !== undefined &&
    (resp.access_token !== undefined ||
      resp.interact !== undefined ||
      resp.subject !== undefined ||
      resp.instance_id !== undefined)
  ) {
    errors.push(
      "When error is present, only continue may also be present (Section 3.6)",
    );
  }

  return errors;
}
