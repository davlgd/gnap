/** Access token types -- RFC 9635 Sections 2.1, 3.2, 5, 6 */

import type { AccessRight } from "./resource.ts";
import type { KeyRef } from "./key.ts";

/** Access token request within a grant request. RFC 9635 Section 2.1 */
export interface AccessTokenRequest {
  access: AccessRight[];
  label?: string;
  flags?: string[];
}

/**
 * Single or multiple access token requests. RFC 9635 Section 2.1
 * Single = object, Multiple = array (each must have a label).
 */
export type AccessTokenRequestField = AccessTokenRequest | AccessTokenRequest[];

/** Access token for continuation requests. RFC 9635 Section 3.1 */
export interface ContinueAccessToken {
  value: string;
}

/** Token management information. RFC 9635 Section 3.2.1 */
export interface TokenManagement {
  uri: string;
  access_token: ContinueAccessToken;
}

/** Access token returned in a grant response. RFC 9635 Section 3.2 */
export interface AccessToken {
  value: string;
  label?: string;
  manage?: TokenManagement;
  access: AccessRight[];
  expires_in?: number;
  key?: KeyRef;
  flags?: string[];
}

/**
 * Single or multiple access tokens in a response. RFC 9635 Section 3.2
 * Single = object, Multiple = array (each has a label).
 */
export type AccessTokenResponseField = AccessToken | AccessToken[];

/** Continuation information in a grant response. RFC 9635 Section 3.1 */
export interface ContinueResponse {
  access_token: ContinueAccessToken;
  uri: string;
  wait?: number;
}

/**
 * Continuation request body. RFC 9635 Section 5.1/5.3
 * Can include interact_ref (post-interaction) or updated grant fields (modification).
 */
export interface ContinueRequest {
  interact_ref?: string;
  access_token?: AccessTokenRequestField;
  subject?: import("./subject.ts").SubjectRequest;
}

/** Token management: rotation response. RFC 9635 Section 6.1 */
export interface TokenRotationResponse {
  access_token: AccessToken;
}

export function isMultipleTokenRequest(
  field: AccessTokenRequestField,
): field is AccessTokenRequest[] {
  return Array.isArray(field);
}

export function isMultipleTokenResponse(
  field: AccessTokenResponseField,
): field is AccessToken[] {
  return Array.isArray(field);
}
