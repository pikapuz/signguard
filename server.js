// wildcard-guard — HTTP server.
//   GET  /           demo UI (single page)
//   GET  /health     {"status":"ok"}
//   POST /api/guard  { chainId, to, value, data, from? } -> verdict
//
// Zero dependencies: Node.js standard library only. No API keys, no signing,
// no wallet connection — the guard only READS public chain data.

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { analyzeTransaction, ValidationError, CHAINS } from "./guard.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const MAX_BODY_BYTES = 64 * 1024;

const indexHtml = await readFile(path.join(__dirname, "public", "index.html"), "utf8");

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new ValidationError("request body too large (max 64 KB)"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const started = Date.now();
  try {
    const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(indexHtml);
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, { status: "ok" });
      return;
    }

    if (req.method === "OPTIONS" && url.pathname === "/api/guard") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/guard") {
      const raw = await readBody(req);
      let input;
      try {
        input = JSON.parse(raw);
      } catch {
        sendJson(res, 400, { error: "request body must be valid JSON" });
        return;
      }
      try {
        const result = await analyzeTransaction(input);
        sendJson(res, 200, result);
      } catch (err) {
        if (err instanceof ValidationError) {
          sendJson(res, 400, { error: err.message });
        } else {
          console.error("guard error:", err);
          sendJson(res, 500, { error: "internal error while analyzing the transaction" });
        }
      }
      return;
    }

    sendJson(res, 404, { error: "not found" });
  } catch (err) {
    console.error("server error:", err);
    if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
  } finally {
    console.log(
      `${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - started}ms)`
    );
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`wildcard-guard listening on http://localhost:${PORT}`);
  console.log(`supported chains: ${Object.entries(CHAINS).map(([id, c]) => `${c.name} (${id})`).join(", ")}`);
});
