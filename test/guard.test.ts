import { test } from "node:test";
import assert from "node:assert/strict";
import { createPwnedGuard, isPwned } from "../src/guard.ts";

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

function mockFetch(counts: Record<string, number> = { [PASSWORD_SUFFIX]: 9_659_365 }) {
  const calls: string[] = [];
  const body = Object.entries(counts)
    .map(([suffix, count]) => `${suffix}:${count}`)
    .join("\r\n");

  const impl = (async (url: string | URL | Request) => {
    calls.push(String(url));
    return new Response(body, { status: 200 });
  }) as unknown as typeof fetch;

  return { impl, calls };
}

function failingFetch() {
  return (async () => {
    throw new Error("network down");
  }) as unknown as typeof fetch;
}

test("rejects a password present in the corpus", async () => {
  const { impl } = mockFetch();
  const result = await createPwnedGuard({ fetchImpl: impl }).check("password");

  assert.equal(result.pwned, true);
  assert.equal(result.allowed, false);
  assert.equal(result.count, 9_659_365);
  assert.equal(result.reason, "breached");
  assert.equal(result.source, "network");
});

test("accepts a password whose suffix is not in the range", async () => {
  const { impl } = mockFetch({ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: 3 });
  const result = await createPwnedGuard({ fetchImpl: impl }).check("password");

  assert.equal(result.pwned, false);
  assert.equal(result.allowed, true);
  assert.equal(result.count, 0);
  assert.equal(result.reason, "ok");
});

test("maxBreaches tolerates a password below the threshold", async () => {
  const { impl } = mockFetch({ [PASSWORD_SUFFIX]: 5 });
  const guard = createPwnedGuard({ fetchImpl: impl, maxBreaches: 10 });
  const result = await guard.check("password");

  assert.equal(result.pwned, true, "still reported as breached");
  assert.equal(result.allowed, true, "but allowed by policy");
});

test("the password and its full hash never reach the network", async () => {
  const { impl, calls } = mockFetch();
  // A neutral endpoint, so the assertion below is not fooled by the words in
  // the default hostname.
  await createPwnedGuard({ fetchImpl: impl, endpoint: "https://range.test/r" }).check("password");

  assert.deepEqual(calls, ["https://range.test/r/5BAA6"]);

  const requested = calls.join(" ");
  assert.equal(requested.includes("password"), false, "the password must never be sent");
  assert.equal(requested.includes(PASSWORD_SUFFIX), false, "the hash suffix must never be sent");
});

test("a second check of the same prefix is served from cache", async () => {
  const { impl, calls } = mockFetch();
  const guard = createPwnedGuard({ fetchImpl: impl });

  const first = await guard.check("password");
  const second = await guard.check("password");

  assert.equal(first.source, "network");
  assert.equal(second.source, "cache");
  assert.equal(calls.length, 1);
  assert.equal(guard.stats().hits, 1);
});

test("fail-open lets the password through when the API is unreachable", async () => {
  const result = await createPwnedGuard({ fetchImpl: failingFetch() }).check("password");

  assert.equal(result.allowed, true);
  assert.equal(result.source, "error");
  assert.equal(result.reason, "lookup-failed");
  assert.ok(result.error instanceof Error);
});

test("fail-closed blocks the password when the API is unreachable", async () => {
  const guard = createPwnedGuard({ fetchImpl: failingFetch(), errorPolicy: "fail-closed" });
  const result = await guard.check("password");

  assert.equal(result.allowed, false);
  assert.equal(result.reason, "lookup-failed");
});

test("a failed lookup is not cached", async () => {
  let attempts = 0;
  const impl = (async () => {
    attempts += 1;
    throw new Error("network down");
  }) as unknown as typeof fetch;

  const guard = createPwnedGuard({ fetchImpl: impl });
  await guard.check("password");
  await guard.check("password");

  assert.equal(attempts, 2);
});

test("the local blocklist short-circuits before any network call", async () => {
  const { impl, calls } = mockFetch();
  const guard = createPwnedGuard({ fetchImpl: impl, localBlocklist: ["Carissa2026"] });
  const result = await guard.check("carissa2026");

  assert.equal(result.allowed, false);
  assert.equal(result.reason, "blocklisted");
  assert.equal(result.source, "local-blocklist");
  assert.equal(calls.length, 0);
});

test("the length check runs before any network call", async () => {
  const { impl, calls } = mockFetch();
  const result = await createPwnedGuard({ fetchImpl: impl, minLength: 12 }).check("password");

  assert.equal(result.allowed, false);
  assert.equal(result.reason, "too-short");
  assert.equal(calls.length, 0);
});

test("minLength 0 disables the length check", async () => {
  const { impl } = mockFetch({ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: 1 });
  const result = await createPwnedGuard({ fetchImpl: impl, minLength: 0 }).check("ab");
  assert.equal(result.allowed, true);
});

test("clearCache forces the next check back onto the network", async () => {
  const { impl, calls } = mockFetch();
  const guard = createPwnedGuard({ fetchImpl: impl });

  await guard.check("password");
  guard.clearCache();
  await guard.check("password");

  assert.equal(calls.length, 2);
});

test("a negative maxBreaches is rejected at construction time", () => {
  assert.throws(() => createPwnedGuard({ maxBreaches: -1 }), RangeError);
});

test("check rejects non-string input", async () => {
  const guard = createPwnedGuard({ fetchImpl: mockFetch().impl });
  await assert.rejects(() => guard.check(1234 as unknown as string), TypeError);
});

test("isPwned works as a one-shot helper", async () => {
  const { impl } = mockFetch();
  const result = await isPwned("password", { fetchImpl: impl });
  assert.equal(result.pwned, true);
});

test("an explicit undefined option falls back to the default instead of changing policy", async () => {
  const guard = createPwnedGuard({
    fetchImpl: failingFetch(),
    errorPolicy: undefined,
    minLength: undefined,
    maxBreaches: undefined,
  });

  const lookupFailed = await guard.check("correct horse battery");
  assert.equal(lookupFailed.allowed, true, "errorPolicy: undefined must still mean fail-open");

  const tooShort = await guard.check("short");
  assert.equal(tooShort.reason, "too-short", "minLength: undefined must still mean 8");
});

test("maxBreaches: undefined still accepts a clean password", async () => {
  const { impl } = mockFetch({ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: 3 });
  const result = await createPwnedGuard({ fetchImpl: impl, maxBreaches: undefined }).check("password");
  assert.deepEqual([result.allowed, result.reason], [true, "ok"]);
});

test("invalid numeric and policy options are rejected at construction time", () => {
  assert.throws(() => createPwnedGuard({ maxBreaches: Number.NaN }), RangeError);
  assert.throws(() => createPwnedGuard({ minLength: Number.NaN }), RangeError);
  assert.throws(() => createPwnedGuard({ cacheTtlMs: Number.NaN }), RangeError);
  assert.throws(() => createPwnedGuard({ cacheMaxEntries: 0 }), RangeError);
  assert.throws(() => createPwnedGuard({ timeoutMs: 0 }), RangeError, "a 0 ms timeout aborts every lookup");
  assert.throws(() => createPwnedGuard({ errorPolicy: "fail-opne" as never }), TypeError);
});
