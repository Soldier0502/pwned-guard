import { test } from "node:test";
import assert from "node:assert/strict";
import { sha1Hex, splitDigest } from "../src/sha1.ts";

test("sha1Hex matches the published digest for a known password", async () => {
  assert.equal(await sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
});

test("sha1Hex matches the digest of the empty string", async () => {
  assert.equal(await sha1Hex(""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
});

test("sha1Hex handles non-ASCII input as UTF-8", async () => {
  const digest = await sha1Hex("contraseña");
  assert.match(digest, /^[0-9A-F]{40}$/);
  assert.equal(digest, await sha1Hex("contraseña"));
});

test("splitDigest returns a 5-char prefix and a 35-char suffix", async () => {
  const { prefix, suffix } = splitDigest(await sha1Hex("password"));
  assert.equal(prefix, "5BAA6");
  assert.equal(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assert.equal(prefix.length + suffix.length, 40);
});
