#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPwnedGuard } from "./guard.ts";

const USAGE = `pwned-guard - check a password against the public breach corpus

Usage:
  echo -n "my password" | pwned-guard [options]
  pwned-guard [options] < password.txt

The password is read from stdin on purpose: passing it as an argument would
leave it in your shell history and in the process list.

Options:
  --max-breaches <n>   Appearances tolerated before rejecting (default: 0)
  --min-length <n>     Local length check before any network call (default: 8)
  --fail-closed        Reject the password if the API is unreachable
  --timeout <ms>       Request timeout in milliseconds (default: 3000)
  --endpoint <url>     Range API base URL (default: the public one, or a mirror)
  --json               Print the result as JSON
  -h, --help           Show this help

Exit codes:
  0  password accepted
  1  password rejected
  2  usage or runtime error
`;

interface CliOptions {
  maxBreaches: number;
  minLength: number;
  failClosed: boolean;
  timeoutMs: number;
  json: boolean;
  endpoint?: string;
}

export function parseArgs(argv: readonly string[]): CliOptions | "help" {
  const options: CliOptions = {
    maxBreaches: 0,
    minLength: 8,
    failClosed: false,
    timeoutMs: 3000,
    json: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const readNumber = (name: string): number => {
      const raw = argv[i + 1];
      const value = Number.parseInt(raw ?? "", 10);
      if (!Number.isFinite(value) || value < 0) {
        throw new Error(`${name} expects a non-negative integer, got "${raw ?? ""}".`);
      }
      i += 1;
      return value;
    };

    switch (arg) {
      case "-h":
      case "--help":
        return "help";
      case "--max-breaches":
        options.maxBreaches = readNumber(arg);
        break;
      case "--min-length":
        options.minLength = readNumber(arg);
        break;
      case "--timeout":
        options.timeoutMs = readNumber(arg);
        break;
      case "--endpoint": {
        const value = argv[i + 1];
        if (!value || value.startsWith("-")) {
          throw new Error("--endpoint expects a URL.");
        }
        options.endpoint = value;
        i += 1;
        break;
      }
      case "--fail-closed":
        options.failClosed = true;
        break;
      case "--json":
        options.json = true;
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  // Strip a single trailing newline, which `echo` and editors add.
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let options: CliOptions | "help";
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }

  if (options === "help") {
    process.stdout.write(USAGE);
    return 0;
  }

  if (process.stdin.isTTY) {
    process.stderr.write("Reading the password from stdin. Pipe it in, or use --help.\n");
    return 2;
  }

  const password = await readStdin();
  if (!password) {
    process.stderr.write("Empty input: nothing to check.\n");
    return 2;
  }

  const guard = createPwnedGuard({
    maxBreaches: options.maxBreaches,
    minLength: options.minLength,
    errorPolicy: options.failClosed ? "fail-closed" : "fail-open",
    timeoutMs: options.timeoutMs,
    ...(options.endpoint ? { endpoint: options.endpoint } : {}),
  });

  const result = await guard.check(password);

  if (options.json) {
    const { error, ...rest } = result;
    process.stdout.write(`${JSON.stringify({ ...rest, error: error?.message }, null, 2)}\n`);
  } else if (result.reason === "lookup-failed") {
    process.stdout.write(`UNKNOWN  the breach API could not be reached (${result.error?.message ?? ""})\n`);
  } else if (result.pwned) {
    process.stdout.write(`PWNED    seen ${result.count.toLocaleString("en-US")} times in known breaches\n`);
  } else if (!result.allowed) {
    process.stdout.write(`REJECTED ${result.reason}\n`);
  } else {
    process.stdout.write("OK       not found in the breach corpus\n");
  }

  return result.allowed ? 0 : 1;
}

/**
 * True when this file is the process entry point. Paths are compared after
 * `realpath`, because npm runs the bin through a symlink and on Windows
 * `import.meta.url` (`file:///C:/...`) never equals `file://` + argv[1].
 */
function isEntryPoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

// Only run when executed directly, so the module stays importable from tests.
if (isEntryPoint()) {
  main().then(
    (code) => process.exit(code),
    (error: unknown) => {
      process.stderr.write(`${(error as Error).message}\n`);
      process.exit(2);
    },
  );
}
