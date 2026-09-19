import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchRange, parseRangeBody } from "../src/range-client.ts";
import { RangeLookupError } from "../src/errors.ts";

const BODY = ["1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365", "0018A45C4D1DEF81644B54AB7F969B88D65:1", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0"].join("\r\n");

function mockFetch(body: string, init: { status?: number } = {}) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const impl = (async (url: string | URL | Request, options?: RequestInit) => {
    calls.push({ url: String(url), headers: (options?.headers ?? {}) as Record<string, string> });
    return new Response(body, { status: init.status ?? 200 });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

test("parseRangeBody keeps real matches and drops padding entries", () => {
  const parsed = parseRangeBody(BODY);
  assert.equal(parsed.get("1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 9_659_365);
  assert.equal(parsed.has("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), false, "count 0 is padding");
  assert.equal(parsed.size, 2);
});

test("parseRangeBody ignores blank lines and normalises lowercase suffixes", () => {
  const parsed = parseRangeBody("\n\n0018a45c4d1def81644b54ab7f969b88d65:3\r\n\n");
  assert.deepEqual([...parsed.entries()], [["0018A45C4D1DEF81644B54AB7F969B88D65", 3]]);
});

test("parseRangeBody rejects a body that is not a range response", () => {
  // A captive portal or WAF answering 200 must not read as "zero matches".
  assert.throws(() => parseRangeBody("<html><body>Please sign in</body></html>"), RangeLookupError);
  assert.throws(() => parseRangeBody(`${BODY}\r\nAAAA:12`), RangeLookupError, "short suffix");
  assert.throws(() => parseRangeBody("0018A45C4D1DEF81644B54AB7F969B88D65:12abc"), RangeLookupError, "junk count");
});

test("parseRangeBody rejects an empty body", () => {
  assert.throws(() => parseRangeBody(""), RangeLookupError);
  assert.throws(() => parseRangeBody("\r\n\r\n"), RangeLookupError);
});

test("fetchRange turns a garbage 200 into a RangeLookupError", async () => {
  const { impl } = mockFetch("<html>blocked by proxy</html>");
  await assert.rejects(() => fetchRange("5BAA6", { fetchImpl: impl }), RangeLookupError);
});

test("fetchRange sends only the 5-character prefix", async () => {
  const { impl, calls } = mockFetch(BODY);
  await fetchRange("5BAA6", { fetchImpl: impl });

  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith("/5BAA6"), `unexpected url: ${calls[0].url}`);
  assert.equal(calls[0].url.includes("1E4C9B"), false, "the suffix must never be sent");
});

test("fetchRange asks for response padding by default", async () => {
  const { impl, calls } = mockFetch(BODY);
  await fetchRange("5BAA6", { fetchImpl: impl });
  assert.equal(calls[0].headers["Add-Padding"], "true");
});

test("fetchRange rejects a malformed prefix without calling the network", async () => {
  const { impl, calls } = mockFetch(BODY);
  await assert.rejects(() => fetchRange("nope", { fetchImpl: impl }), RangeLookupError);
  assert.equal(calls.length, 0);
});

test("fetchRange turns a non-200 into a RangeLookupError carrying the status", async () => {
  const { impl } = mockFetch("", { status: 503 });
  await assert.rejects(
    () => fetchRange("5BAA6", { fetchImpl: impl }),
    (error: RangeLookupError) => error instanceof RangeLookupError && error.status === 503,
  );
});

test("fetchRange times out when the body never finishes arriving", async () => {
  // Headers arrive at once, then the body stalls forever.
  const impl = (async () =>
    new Response(new ReadableStream({ start() {} }), { status: 200 })) as unknown as typeof fetch;

  const outcome = await Promise.race([
    fetchRange("5BAA6", { fetchImpl: impl, timeoutMs: 30 }).then(
      () => "resolved",
      (error: unknown) => error,
    ),
    new Promise((resolve) => setTimeout(() => resolve("hung"), 1000).unref()),
  ]);

  assert.ok(outcome instanceof RangeLookupError, `expected a RangeLookupError, got: ${String(outcome)}`);
});

test("fetchRange wraps transport failures", async () => {
  const impl = (async () => {
    throw new Error("socket hang up");
  }) as unknown as typeof fetch;
  await assert.rejects(() => fetchRange("5BAA6", { fetchImpl: impl }), RangeLookupError);
});

test("lookup errors never carry the hash prefix, and say what went wrong", async () => {
  const cases: Array<[string, typeof fetch, string]> = [
    ["network", (async () => { throw new Error("socket hang up"); }) as unknown as typeof fetch, "network"],
    ["http", mockFetch("", { status: 503 }).impl, "http"],
    ["malformed", mockFetch("<html></html>").impl, "malformed"],
    ["timeout", (async () => new Response(new ReadableStream({ start() {} }))) as unknown as typeof fetch, "timeout"],
  ];

  for (const [label, impl, code] of cases) {
    const error = await fetchRange("5BAA6", { fetchImpl: impl, timeoutMs: 30 }).then(
      () => undefined,
      (e: RangeLookupError) => e,
    );
    assert.ok(error instanceof RangeLookupError, label);
    assert.equal(error.code, code, label);
    // 5 hex chars are 20 bits of the password hash: they must not end up in a log next to a user id.
    assert.equal(error.message.includes("5BAA6"), false, `${label}: ${error.message}`);
  }
});
