export { PwnedGuard, createPwnedGuard, isPwned } from "./guard.ts";
export type { PwnedGuardOptions, CheckResult, CheckSource, ErrorPolicy } from "./guard.ts";
export { fetchRange, parseRangeBody, DEFAULT_ENDPOINT, DEFAULT_USER_AGENT } from "./range-client.ts";
export type { RangeClientOptions } from "./range-client.ts";
export { sha1Hex, splitDigest } from "./sha1.ts";
export { TtlCache } from "./cache.ts";
export { PwnedGuardError, RangeLookupError } from "./errors.ts";
export type { RangeLookupErrorCode } from "./errors.ts";

export const VERSION = "0.1.0";
