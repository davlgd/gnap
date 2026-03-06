/** Grant request and response types -- RFC 9635 Sections 2, 3 */

import type { AccessTokenRequestField, AccessTokenResponseField, ContinueResponse } from "./token.ts";
import type { ClientInstance } from "./client.ts";
import type { InteractRequest, InteractResponse } from "./interaction.ts";
import type { SubjectRequest, SubjectResponse, SubjectAssertion } from "./subject.ts";
import type { GnapErrorField } from "./error.ts";

/** Inline user information. RFC 9635 Section 2.4 */
export interface UserInfo {
  sub_ids?: unknown[];
  assertions?: SubjectAssertion[];
}

/**
 * User reference in a grant request. RFC 9635 Section 2.4
 * Either a string reference or an inline user info object.
 */
export type UserRef = string | UserInfo;

/** A GNAP grant request sent from the client to the AS. RFC 9635 Section 2 */
export interface GrantRequest {
  access_token?: AccessTokenRequestField;
  client: ClientInstance;
  interact?: InteractRequest;
  subject?: SubjectRequest;
  user?: UserRef;
}

/** A GNAP grant response from the AS. RFC 9635 Section 3 */
export interface GrantResponse {
  continue?: ContinueResponse;
  access_token?: AccessTokenResponseField;
  interact?: InteractResponse;
  subject?: SubjectResponse;
  instance_id?: string;
  error?: GnapErrorField;
}
