/** GNAP error types -- RFC 9635 Section 3.6 */

/** GNAP error codes from the IANA "GNAP Error Codes" registry. */
export const GnapErrorCode = {
  InvalidRequest: "invalid_request",
  InvalidClient: "invalid_client",
  InvalidInteraction: "invalid_interaction",
  InvalidFlag: "invalid_flag",
  InvalidRotation: "invalid_rotation",
  KeyRotationNotSupported: "key_rotation_not_supported",
  InvalidContinuation: "invalid_continuation",
  UserDenied: "user_denied",
  RequestDenied: "request_denied",
  UnknownUser: "unknown_user",
  UnknownInteraction: "unknown_interaction",
  TooFast: "too_fast",
  TooManyAttempts: "too_many_attempts",
} as const;

export type GnapErrorCode =
  | (typeof GnapErrorCode)[keyof typeof GnapErrorCode]
  | (string & {});

/** Error response object from the AS. RFC 9635 Section 3.6 */
export interface GnapError {
  code: GnapErrorCode;
  description?: string;
}

/**
 * Error field in a grant response. Can be an object or a string.
 * RFC 9635 Section 3.6: "This field is either an object or a string."
 */
export type GnapErrorField = GnapError | string;

export function isGnapErrorObject(err: GnapErrorField): err is GnapError {
  return typeof err === "object" && "code" in err;
}

export function getErrorCode(err: GnapErrorField): string {
  return isGnapErrorObject(err) ? err.code : err;
}

/** Library-level error for compliance operations. */
export class GnapComplianceError extends Error {
  constructor(
    public readonly kind: "json" | "validation" | "crypto",
    message: string,
  ) {
    super(message);
    this.name = "GnapComplianceError";
  }

  static json(message: string) {
    return new GnapComplianceError("json", message);
  }

  static validation(message: string) {
    return new GnapComplianceError("validation", message);
  }

  static crypto(message: string) {
    return new GnapComplianceError("crypto", message);
  }
}
