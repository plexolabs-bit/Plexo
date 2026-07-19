#!/usr/bin/env node
// StellarHub ZK reference · https://stellarhub.io
//
// serve.mjs — zero-dependency static server for the in-browser ZK proof
// playground (demo/web/index.html). Node's built-in http only — no npm install,
// works offline. Serves from the repo root so the page can fetch the committed
// circuit artefacts under /build/ and the snarkjs bundle under /demo/web/vendor/.
//
// The `application/wasm` MIME type is required: browsers refuse to instantiate a
// wasm module served as octet-stream, which would break snarkjs proof generation.
//
// Usage:
//   node demo/serve.mjs            # http://localhost:8788  (auto-bumps if busy)
//   PORT=9000 node demo/serve.mjs

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { resolve, join, normalize, extname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const START_PORT = Number(process.env.PORT) || 8788;
const HOST = "127.0.0.1";
const INDEX = "/demo/web/index.html";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".zkey": "application/octet-stream",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function send(res, code, body, headers = {}) {
  res.writeHead(code, { "cache-control": "no-store", ...headers });
  res.end(body);
}

const server = createServer(async (req, res) => {
  try {
    let pathname = decodeURIComponent(new URL(req.url, `http://${HOST}`).pathname);
    if (pathname === "/" || pathname === "/demo/web" || pathname === "/demo/web/") {
      pathname = INDEX;
    }

    // Resolve inside ROOT and reject path traversal.
    const filePath = normalize(join(ROOT, pathname));
    if (!filePath.startsWith(ROOT)) return send(res, 403, "forbidden");

    const info = await stat(filePath).catch(() => null);
    if (!info || !info.isFile()) return send(res, 404, `not found: ${pathname}`);

    const body = await readFile(filePath);
    const type = MIME[extname(filePath).toLowerCase()] || "application/octet-stream";
    send(res, 200, body, { "content-type": type, "content-length": info.size });
  } catch (err) {
    send(res, 500, `server error: ${err?.message ?? err}`);
  }
});

// Bump the port a few times if the default is taken, then give up cleanly.
function listen(port, attemptsLeft) {
  server.once("error", (err) => {
    if (err.code === "EADDRINUSE" && attemptsLeft > 0) {
      listen(port + 1, attemptsLeft - 1);
    } else {
      console.error(`[serve] cannot bind ${HOST}:${port} — ${err.message}`);
      process.exit(1);
    }
  });
  server.listen(port, HOST, () => {
    const url = `http://${HOST}:${port}/`;
    console.log("");
    console.log("  StellarHub · Confidential Send — ZK proof playground");
    console.log("  ────────────────────────────────────────────────────");
    console.log(`  ▸ open  ${url}`);
    console.log("  ▸ click “Generate ZK proof” — a real Groth16 proof runs in your browser");
    console.log("  ▸ Ctrl+C to stop");
    console.log("");
  });
}

listen(START_PORT, 10);
