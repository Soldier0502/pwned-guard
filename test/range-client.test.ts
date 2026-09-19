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

test("parseRangeBody ignores blank and malformed lines", () => {
  const parsed = parseRangeBody("\n\nnot-a-line\nAAAA:12\n");
  assert.deepEqual([...parsed.entries()], [["AAAA", 12]]);
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

test("fetchRange wraps transport failures", async () => {
  const impl = (async () => {
    throw new Error("socket hang up");
  }) as unknown as typeof fetch;
  await assert.rejects(() => fetchRange("5BAA6", { fetchImpl: impl }), RangeLookupError);
});
