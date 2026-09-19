/** Base error for every failure raised by this package. */
export class PwnedGuardError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PwnedGuardError";
  }
}

/** The range API could not be reached, timed out, or answered with a non-200. */
export class RangeLookupError extends PwnedGuardError {
  readonly status?: number;

  constructor(message: string, options?: { cause?: unknown; status?: number }) {
    super(message, options);
    this.name = "RangeLookupError";
    this.status = options?.status;
  }
}
