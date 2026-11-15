// Vercel serverless function: POST /api/guard
// Same behavior as the POST /api/guard route in server.js — the local
// Node server and this function share guard.js, so verdicts are identical.
import { analyzeTransaction, ValidationError } from "../guard.js";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ error: "method not allowed, use POST" });
    return;
  }

  let input = req.body;
  if (typeof input === "string") {
    try {
      input = JSON.parse(input);
    } catch {
      res.status(400).json({ error: "request body must be valid JSON" });
      return;
    }
  }

  try {
    const result = await analyzeTransaction(input);
    res.status(200).json(result);
  } catch (err) {
    if (err instanceof ValidationError) {
      res.status(400).json({ error: err.message });
    } else {
      console.error("guard error:", err);
      res.status(500).json({ error: "internal error while analyzing the transaction" });
    }
  }
}
