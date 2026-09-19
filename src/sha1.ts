import { PwnedGuardError } from "./errors.ts";

/**
 * SHA-1 of a UTF-8 string, uppercase hex.
 *
 * Uses Web Crypto, which is available in Node 18+, Deno, Bun, Cloudflare
 * Workers, Vercel Edge and modern browsers. That keeps this package free of
 * dependencies and usable from any runtime.
 *
 * SHA-1 is used here because it is the hash the range API is built on. It is
 * never used to store anything: the digest exists only long enough to derive a
 * 5-character prefix.
 */
export async function sha1Hex(input: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new PwnedGuardError(
      "Web Crypto is not available in this runtime. Node 18+, Deno, Bun, " +
        "workers and browsers all provide globalThis.crypto.subtle.",
    );
  }

  const bytes = new TextEncoder().encode(input);
  const digest = await subtle.digest("SHA-1", bytes);

  let hex = "";
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex.toUpperCase();
}

/** Splits a SHA-1 digest into the 5-char prefix sent upstream and the suffix kept local. */
export function splitDigest(digest: string): { prefix: string; suffix: string } {
  return { prefix: digest.slice(0, 5), suffix: digest.slice(5) };
}
