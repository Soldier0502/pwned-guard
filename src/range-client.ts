import { RangeLookupError } from "./errors.ts";

export const DEFAULT_ENDPOINT = "https://api.pwnedpasswords.com/range";
export const DEFAULT_USER_AGENT = "pwned-guard (+https://github.com/Soldier0502/pwned-guard)";

export interface RangeClientOptions {
  /** Base URL of the range endpoint. Override it to point at your own mirror. */
  endpoint?: string;
  /** Abort the request after this many milliseconds. */
  timeoutMs?: number;
  /** Injectable fetch, mainly for tests and for runtimes with a custom agent. */
  fetchImpl?: typeof fetch;
  /** Sent as the User-Agent header. Identify your service; it is good manners. */
  userAgent?: string;
  /**
   * Ask the API to pad the response with fake entries so that the response
   * size leaks nothing about how many real matches the prefix has.
   */
  addPadding?: boolean;
}

/**
 * Fetches every SHA-1 suffix known for a 5-character prefix.
 *
 * This is the k-anonymity half of the design: the caller sends 5 hex
 * characters, gets back ~800 suffixes, and does the actual comparison locally.
 * The password never leaves the process, and neither does its full hash.
 */
export async function fetchRange(
  prefix: string,
  options: RangeClientOptions = {},
): Promise<Map<string, number>> {
  if (!/^[0-9A-F]{5}$/.test(prefix)) {
    throw new RangeLookupError(`Invalid prefix: expected 5 uppercase hex characters, got "${prefix}".`);
  }

  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? 3000;
  const doFetch = options.fetchImpl ?? globalThis.fetch;

  if (typeof doFetch !== "function") {
    throw new RangeLookupError("No fetch implementation available. Pass options.fetchImpl.");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await doFetch(`${endpoint}/${prefix}`, {
      method: "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": options.userAgent ?? DEFAULT_USER_AGENT,
        ...(options.addPadding === false ? {} : { "Add-Padding": "true" }),
      },
    });
  } catch (cause) {
    throw new RangeLookupError(`Range lookup for ${prefix} failed.`, { cause });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new RangeLookupError(`Range lookup for ${prefix} returned HTTP ${response.status}.`, {
      status: response.status,
    });
  }

  return parseRangeBody(await response.text());
}

/**
 * Parses the `SUFFIX:COUNT` body.
 *
 * Padding entries come back with a count of 0 and are dropped here, so the
 * rest of the code never has to know padding exists.
 */
export function parseRangeBody(body: string): Map<string, number> {
  const suffixes = new Map<string, number>();

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;

    const separator = line.indexOf(":");
    if (separator === -1) continue;

    const suffix = line.slice(0, separator).toUpperCase();
    const count = Number.parseInt(line.slice(separator + 1), 10);

    if (!Number.isFinite(count) || count <= 0) continue;
    suffixes.set(suffix, count);
  }

  return suffixes;
}
