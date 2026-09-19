#!/usr/bin/env node
// Local stand-in for the range API, so the README demo is reproducible offline.
//
//   node scripts/demo-server.mjs            # listens on 127.0.0.1:8787
//   printf 'password' | pwned-guard --endpoint http://127.0.0.1:8787/range
//
// It knows one real entry: SHA-1("password") = 5BAA6 + 1E4C9B93..., with the
// count the public corpus reports. Every other prefix gets padding only.
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 8787);
const PADDING = "0000000000000000000000000000000000F:0";
const RANGES = {
  "5BAA6": ["1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365", PADDING],
};

createServer((request, response) => {
  const match = /^\/range\/([0-9A-F]{5})$/.exec(request.url ?? "");
  if (!match) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "Content-Type": "text/plain" });
  response.end((RANGES[match[1]] ?? [PADDING]).join("\r\n"));
}).listen(PORT, "127.0.0.1", () => {
  console.error(`demo range API on http://127.0.0.1:${PORT}/range`);
});
