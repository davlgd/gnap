/** Access rights and resource types -- RFC 9635 Section 8 */

/** A structured access right definition. RFC 9635 Section 8.1 */
export interface StructuredAccessRight {
  type: string;
  actions?: string[];
  locations?: string[];
  datatypes?: string[];
  identifier?: string;
  privileges?: string[];
}

/**
 * A single access right, either a string reference or a structured object.
 * RFC 9635 Section 8
 */
export type AccessRight = string | StructuredAccessRight;

export function isStructuredAccessRight(
  right: AccessRight,
): right is StructuredAccessRight {
  return typeof right === "object" && "type" in right;
}
