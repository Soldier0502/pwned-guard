/** Base error for every failure raised by this package. */
export class PwnedGuardError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PwnedGuardError";
  }
}

/** Why a lookup failed. Stable, so callers can alert on it without parsing messages. */
export type RangeLookupErrorCode = "timeout" | "network" | "http" | "malformed" | "invalid-input";

/**
 * The range API could not be reached, timed out, or answered with something
 * that is not a range response.
 *
 * Messages never include the hash prefix: it is 20 bits of the password hash,
 * and error messages tend to be logged next to a user identifier.
 */
export class RangeLookupError extends PwnedGuardError {
  readonly status?: number;
  readonly code: RangeLookupErrorCode;

  constructor(message: string, options?: { cause?: unknown; status?: number; code?: RangeLookupErrorCode }) {
    super(message, options);
    this.name = "RangeLookupError";
    this.status = options?.status;
    this.code = options?.code ?? "network";
  }
}
