import { RangeLookupError } from "./errors.ts";
import { TtlCache } from "./cache.ts";
import { fetchRange, type RangeClientOptions } from "./range-client.ts";
import { sha1Hex, splitDigest } from "./sha1.ts";

/** What to do when the breach API cannot be reached. */
export type ErrorPolicy = "fail-open" | "fail-closed";

export type CheckSource = "network" | "cache" | "local-blocklist" | "policy" | "error";

export interface CheckResult {
  /** Whether the password may be used. This is the only field most callers need. */
  allowed: boolean;
  /** Whether the password appears in the breach corpus. */
  pwned: boolean;
  /** How many times it appears. 0 when unknown or clean. */
  count: number;
  /** Where the verdict came from. Useful for metrics and for debugging cache behaviour. */
  source: CheckSource;
  /** Stable machine-readable reason, safe to map to a translated message. */
  reason: "ok" | "too-short" | "blocklisted" | "breached" | "lookup-failed";
  /** Present only when the lookup failed. */
  error?: Error;
}

export interface PwnedGuardOptions extends RangeClientOptions {
  /**
   * How many breach appearances are tolerated before a password is rejected.
   * 0 means "reject anything that appears at all", which is the right default
   * for new passwords. Raise it if you are retrofitting an existing user base
   * and want to start by blocking only the most common ones.
   */
  maxBreaches?: number;
  /**
   * What happens when the API is unreachable. `fail-open` accepts the password
   * (availability first, the default) and `fail-closed` rejects it.
   * Whichever you pick, log the `source: "error"` results.
   */
  errorPolicy?: ErrorPolicy;
  /** Minimum length enforced locally before any network call. Set 0 to disable. */
  minLength?: number;
  /** Passwords rejected without any network call: your product name, brand terms, etc. */
  localBlocklist?: Iterable<string>;
  /** Cache TTL for prefix responses. Prefix ranges change slowly; an hour is plenty. */
  cacheTtlMs?: number;
  /** Maximum number of cached prefixes. Each holds ~800 short strings. */
  cacheMaxEntries?: number;
  /** Injectable clock, for tests. */
  now?: () => number;
}

const DEFAULTS = {
  maxBreaches: 0,
  errorPolicy: "fail-open" as ErrorPolicy,
  minLength: 8,
  cacheTtlMs: 60 * 60 * 1000,
  cacheMaxEntries: 1024,
};

/**
 * Checks passwords against the public breach corpus without ever sending the
 * password, or its full hash, anywhere.
 *
 * Never log the password you pass in, and never log the returned `count`
 * alongside a user identifier: together they narrow down the password.
 */
export class PwnedGuard {
  private readonly options: Required<Pick<PwnedGuardOptions, keyof typeof DEFAULTS>> & PwnedGuardOptions;
  private readonly cache: TtlCache<string, Map<string, number>>;
  private readonly blocklist: Set<string>;

  constructor(options: PwnedGuardOptions = {}) {
    this.options = { ...DEFAULTS, ...options };

    if (this.options.maxBreaches < 0) {
      throw new RangeError("maxBreaches must be >= 0.");
    }

    this.cache = new TtlCache({
      ttlMs: this.options.cacheTtlMs,
      maxEntries: this.options.cacheMaxEntries,
      now: options.now,
    });

    this.blocklist = new Set(
      [...(options.localBlocklist ?? [])].map((entry) => entry.normalize("NFKC").toLowerCase()),
    );
  }

  /** Runs every check in order, cheapest first. */
  async check(password: string): Promise<CheckResult> {
    if (typeof password !== "string") {
      throw new TypeError("password must be a string.");
    }

    if (this.options.minLength > 0 && password.length < this.options.minLength) {
      return { allowed: false, pwned: false, count: 0, source: "policy", reason: "too-short" };
    }

    if (this.blocklist.has(password.normalize("NFKC").toLowerCase())) {
      return { allowed: false, pwned: false, count: 0, source: "local-blocklist", reason: "blocklisted" };
    }

    const { prefix, suffix } = splitDigest(await sha1Hex(password));

    let suffixes = this.cache.get(prefix);
    let source: CheckSource = "cache";

    if (!suffixes) {
      source = "network";
      try {
        suffixes = await fetchRange(prefix, this.options);
        this.cache.set(prefix, suffixes);
      } catch (cause) {
        const error = cause instanceof Error ? cause : new RangeLookupError(String(cause));
        return {
          allowed: this.options.errorPolicy === "fail-open",
          pwned: false,
          count: 0,
          source: "error",
          reason: "lookup-failed",
          error,
        };
      }
    }

    const count = suffixes.get(suffix) ?? 0;
    const pwned = count > 0;

    return {
      allowed: count <= this.options.maxBreaches,
      pwned,
      count,
      source,
      reason: count > this.options.maxBreaches ? "breached" : "ok",
    };
  }

  /** Cache counters, handy to expose as metrics. */
  stats(): { hits: number; misses: number; size: number } {
    return this.cache.stats;
  }

  /** Drops every cached prefix. */
  clearCache(): void {
    this.cache.clear();
  }
}

/** Convenience factory, so callers do not have to import the class. */
export function createPwnedGuard(options: PwnedGuardOptions = {}): PwnedGuard {
  return new PwnedGuard(options);
}

/**
 * One-shot check for scripts and tests. Creates a throwaway guard, so it does
 * not share a cache: use {@link createPwnedGuard} in a long-lived service.
 */
export async function isPwned(password: string, options: PwnedGuardOptions = {}): Promise<CheckResult> {
  return new PwnedGuard(options).check(password);
}
