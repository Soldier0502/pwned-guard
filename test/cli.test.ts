import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../src/cli.ts";

test("defaults are conservative", () => {
  assert.deepEqual(parseArgs([]), {
    maxBreaches: 0,
    minLength: 8,
    failClosed: false,
    timeoutMs: 3000,
    json: false,
  });
});

test("parses every supported flag", () => {
  const options = parseArgs(["--max-breaches", "5", "--min-length", "12", "--timeout", "1500", "--fail-closed", "--json"]);
  assert.deepEqual(options, {
    maxBreaches: 5,
    minLength: 12,
    failClosed: true,
    timeoutMs: 1500,
    json: true,
  });
});

test("--endpoint is parsed and validated", () => {
  assert.equal(parseArgs(["--endpoint", "https://range.internal/r"]).endpoint, "https://range.internal/r");
  assert.throws(() => parseArgs(["--endpoint", "--json"]), /expects a URL/);
});

test("--help short-circuits", () => {
  assert.equal(parseArgs(["--help"]), "help");
  assert.equal(parseArgs(["-h"]), "help");
});

test("an unknown flag is an error", () => {
  assert.throws(() => parseArgs(["--nope"]), /Unknown option/);
});

test("a non-numeric value is an error", () => {
  assert.throws(() => parseArgs(["--max-breaches", "many"]), /non-negative integer/);
});

test("a negative value is an error", () => {
  assert.throws(() => parseArgs(["--timeout", "-5"]), /non-negative integer/);
});
