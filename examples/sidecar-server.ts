// A tiny HTTP sidecar, for backends that are not written in JavaScript
// (.NET, PHP, Python, Go...). Run it next to your app and call it over
// loopback; the password never leaves the machine except as a 5-character
// hash prefix, which the sidecar sends, not your app.
//
// Copy this file into a project that has the package installed, then:
//
//   node sidecar-server.ts        (Node 22.18+ runs TypeScript directly)
//   curl -s localhost:8787/check -d '{"password":"..."}' -H 'content-type: application/json'
//
// Bind to 127.0.0.1 only. Never expose this port to a network.
import { createServer } from "node:http";
import { createPwnedGuard } from "@soldier0502/pwned-guard";

const guard = createPwnedGuard({ minLength: 10, errorPolicy: "fail-open" });
const PORT = Number(process.env.PORT ?? 8787);
const MAX_BODY_BYTES = 4096;

const server = createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/check") {
    res.writeHead(404).end();
    return;
  }

  // A password fits in a few bytes; refuse anything that is clearly not one.
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) {
      res.writeHead(413).end();
      return;
    }
    chunks.push(chunk as Buffer);
  }

  try {
    const { password } = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { password?: unknown };

    if (typeof password !== "string") {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "password must be a string" }));
      return;
    }

    const { allowed, pwned, count, reason, source } = await guard.check(password);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ allowed, pwned, count, reason, source }));
  } catch {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid json" }));
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`pwned-guard sidecar listening on http://127.0.0.1:${PORT}`);
});
