/** Interaction types -- RFC 9635 Sections 2.5, 3.3, 4 */

/**
 * Start mode for interaction.
 * RFC 9635 Section 2.5.1: either a string or an extended mode object.
 */
export type StartMode = string | ExtendedStartMode;

/** Extended start mode object. RFC 9635 Section 2.5.1: MUST contain `mode` field. */
export interface ExtendedStartMode {
  mode: string;
  [key: string]: unknown;
}

export function isExtendedStartMode(
  mode: StartMode,
): mode is ExtendedStartMode {
  return typeof mode === "object" && "mode" in mode;
}

/** Finish method for interaction callback. RFC 9635 Section 2.5.2 */
export interface InteractFinish {
  method: string;
  uri: string;
  nonce: string;
  hash_method?: string;
}

/** Hints for interaction preferences. RFC 9635 Section 2.5.3 */
export interface InteractHints {
  ui_locales?: string[];
}

/** Interaction request from client to AS. RFC 9635 Section 2.5 */
export interface InteractRequest {
  start: StartMode[];
  finish?: InteractFinish;
  hints?: InteractHints;
}

/** User code with URI for direct entry. RFC 9635 Section 3.3.4 */
export interface UserCodeUri {
  code: string;
  uri: string;
}

/** Interaction response from AS to client. RFC 9635 Section 3.3 */
export interface InteractResponse {
  redirect?: string;
  app?: string;
  user_code?: string;
  user_code_uri?: UserCodeUri;
  finish?: string;
  expires_in?: number;
}
