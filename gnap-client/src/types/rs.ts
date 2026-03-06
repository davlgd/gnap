/**
 * Resource Server connection types -- RFC 9767
 * Covers discovery, introspection, resource registration, and token derivation.
 */

import type { AccessRight } from "./resource.ts";
import type { KeyRef } from "./key.ts";

/** AS discovery response for Resource Servers. RFC 9767 Section 3 */
export interface AsDiscoveryResponse {
  grant_request_endpoint: string;
  key_proofs_supported?: string[];
  introspection_endpoint?: string;
  resource_registration_endpoint?: string;
  token_formats_supported?: string[];
}

/** Token introspection request body. RFC 9767 Section 4 */
export interface IntrospectionRequest {
  access_token: string;
  proof?: string;
  resource_server?: KeyRef;
  access?: AccessRight[];
}

/** Token introspection response. RFC 9767 Section 4 */
export interface IntrospectionResponse {
  active: boolean;
  access?: AccessRight[];
  key?: KeyRef;
  flags?: string[];
  expires_in?: number;
}

/** Resource set registration request. RFC 9767 Section 5 */
export interface ResourceRegistrationRequest {
  resource_set: AccessRight[];
  resource_server?: KeyRef;
}

/** Resource set registration response. RFC 9767 Section 5 */
export interface ResourceRegistrationResponse {
  resource_reference: string;
}
