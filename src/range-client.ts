import { RangeLookupError } from "./errors.ts";

export const DEFAULT_ENDPOINT = "https://api.pwnedpasswords.com/range";
export const DEFAULT_USER_AGENT = "pwned-guard (+https://github.com/Soldier0502/pwned-guard)";

const RANGE_LINE = /^([0-9A-Fa-f]{35}):(\d+)$/;

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
    throw new RangeLookupError("Invalid prefix: expected 5 uppercase hex characters.", { code: "invalid-input" });
  }

  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? 3000;
  const doFetch = options.fetchImpl ?? globalThis.fetch;

  if (typeof doFetch !== "function") {
    throw new RangeLookupError("No fetch implementation available. Pass options.fetchImpl.", { code: "invalid-input" });
  }

  const controller = new AbortController();
  // The deadline covers the whole exchange, body included: a server that sends
  // headers and then stalls must not hang the caller.
  const deadline = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () => reject(new Error(`Timed out after ${timeoutMs} ms.`)), {
      once: true,
    });
  });
  deadline.catch(() => {});
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let body: string;
  try {
    const response = await Promise.race([
      doFetch(`${endpoint}/${prefix}`, {
        method: "GET",
        signal: controller.signal,
        headers: {
          "User-Agent": options.userAgent ?? DEFAULT_USER_AGENT,
          ...(options.addPadding === false ? {} : { "Add-Padding": "true" }),
        },
      }),
      deadline,
    ]);

    if (!response.ok) {
      throw new RangeLookupError(`Range lookup returned HTTP ${response.status}.`, {
        status: response.status,
        code: "http",
      });
    }

    body = await Promise.race([response.text(), deadline]);
  } catch (cause) {
    if (cause instanceof RangeLookupError) throw cause;
    const timedOut = controller.signal.aborted;
    throw new RangeLookupError(timedOut ? `Range lookup timed out after ${timeoutMs} ms.` : "Range lookup failed.", {
      cause,
      code: timedOut ? "timeout" : "network",
    });
  } finally {
    clearTimeout(timer);
  }

  return parseRangeBody(body);
}

/**
 * Parses the `SUFFIX:COUNT` body.
 *
 * Padding entries come back with a count of 0 and are dropped here, so the
 * rest of the code never has to know padding exists.
 *
 * Parsing is strict on purpose. A captive portal, proxy or WAF can answer 200
 * with an HTML page; reading that as "no matches" would accept every password
 * and sidestep `fail-closed`. Anything that is not a range response throws.
 */
export function parseRangeBody(body: string): Map<string, number> {
  const suffixes = new Map<string, number>();
  let lines = 0;

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;

    const match = RANGE_LINE.exec(line);
    if (!match) {
      throw new RangeLookupError("Range response is malformed: expected SUFFIX:COUNT lines.", { code: "malformed" });
    }
    lines += 1;

    const count = Number.parseInt(match[2]!, 10);
    if (count <= 0) continue;
    suffixes.set(match[1]!.toUpperCase(), count);
  }

  // Every real prefix has hundreds of suffixes, so an empty body is a failure.
  if (lines === 0) {
    throw new RangeLookupError("Range response is empty.", { code: "malformed" });
  }

  return suffixes;
}
