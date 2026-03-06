/** Client instance types -- RFC 9635 Section 2.3 */

import type { KeyRef } from "./key.ts";

/** Display information for a client instance. RFC 9635 Section 2.3.2 */
export interface ClientDisplay {
  name?: string;
  uri?: string;
  logo_uri?: string;
}

/** Inline client instance information. RFC 9635 Section 2.3.1 */
export interface ClientInstanceInfo {
  key: KeyRef;
  class_id?: string;
  display?: ClientDisplay;
}

/**
 * Client instance identification.
 * Can be a reference string or an inline object.
 * RFC 9635 Section 2.3
 */
export type ClientInstance = string | ClientInstanceInfo;

export function isInlineClient(
  client: ClientInstance,
): client is ClientInstanceInfo {
  return typeof client === "object" && "key" in client;
}
