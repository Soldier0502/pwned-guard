import { test } from "node:test";
import assert from "node:assert/strict";
import { TtlCache } from "../src/cache.ts";

function clock(start = 0) {
  let value = start;
  return { now: () => value, advance: (ms: number) => (value += ms) };
}

test("returns a stored value before the TTL expires", () => {
  const time = clock();
  const cache = new TtlCache<string, number>({ ttlMs: 1000, maxEntries: 10, now: time.now });
  cache.set("a", 1);
  time.advance(999);
  assert.equal(cache.get("a"), 1);
});

test("drops a value once the TTL has passed", () => {
  const time = clock();
  const cache = new TtlCache<string, number>({ ttlMs: 1000, maxEntries: 10, now: time.now });
  cache.set("a", 1);
  time.advance(1000);
  assert.equal(cache.get("a"), undefined);
  assert.equal(cache.size, 0);
});

test("evicts the least recently used entry when full", () => {
  const cache = new TtlCache<string, number>({ ttlMs: 10_000, maxEntries: 2 });
  cache.set("a", 1);
  cache.set("b", 2);
  cache.get("a"); // "a" becomes the most recently used
  cache.set("c", 3);

  assert.equal(cache.get("b"), undefined);
  assert.equal(cache.get("a"), 1);
  assert.equal(cache.get("c"), 3);
});

test("counts hits and misses", () => {
  const cache = new TtlCache<string, number>({ ttlMs: 10_000, maxEntries: 4 });
  cache.set("a", 1);
  cache.get("a");
  cache.get("missing");
  assert.deepEqual(cache.stats, { hits: 1, misses: 1, size: 1 });
});

test("a zero TTL disables caching instead of caching forever", () => {
  const cache = new TtlCache<string, number>({ ttlMs: 0, maxEntries: 4 });
  cache.set("a", 1);
  assert.equal(cache.get("a"), undefined);
});
