import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function runCli(args: string[], input = "") {
  return spawnSync(process.execPath, [CLI, ...args], { input, encoding: "utf8" });
}

test("running the CLI file directly prints the usage for --help", () => {
  const result = runCli(["--help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
});

test("running the CLI file directly exits 2 on an unknown flag", () => {
  const result = runCli(["--definitely-not-a-flag"]);
  assert.equal(result.status, 2, "exit 0 would read as 'password accepted'");
  assert.match(result.stderr, /Unknown option/);
});

test("running the CLI file directly rejects a too-short password without any network call", () => {
  const result = runCli([], "short");
  assert.equal(result.status, 1);
  assert.match(result.stdout, /REJECTED/);
});

// Port 1 on loopback refuses the connection at once: a real failure, no external network.
const UNREACHABLE = ["--endpoint", "http://127.0.0.1:1/range"];

test("an unreachable API exits 3 under fail-open, so scripts cannot mistake it for 'accepted'", () => {
  const result = runCli(UNREACHABLE, "correct horse battery staple");
  assert.equal(result.status, 3);
  assert.match(result.stdout, /UNKNOWN/);
});

test("an unreachable API exits 1 under --fail-closed", () => {
  const result = runCli([...UNREACHABLE, "--fail-closed"], "correct horse battery staple");
  assert.equal(result.status, 1);
});
