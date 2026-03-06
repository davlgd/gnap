/** Subject information types -- RFC 9635 Sections 2.2 and 3.4 */

/** Subject information request. RFC 9635 Section 2.2 */
export interface SubjectRequest {
  sub_ids?: unknown[];
  sub_id_formats?: string[];
  assertion_formats?: string[];
}

/** A subject identifier. RFC 9635 Section 3.4.1 */
export interface SubjectIdentifier {
  format: string;
  [key: string]: unknown;
}

/** A subject assertion. RFC 9635 Section 3.4.2 */
export interface SubjectAssertion {
  format: string;
  value: string;
}

/** Subject information response. RFC 9635 Section 3.4 */
export interface SubjectResponse {
  sub_ids?: SubjectIdentifier[];
  assertions?: SubjectAssertion[];
  updated_at?: string;
}
