// wildcard-guard — EVM wallet & transaction guard.
// Screens a transaction (or token approval) BEFORE the user signs it, using
// only free public JSON-RPC reads. No API keys, no signing, no wallet access.
//
// How it works:
//   1. Validate and decode the calldata (approve, transfer, setApprovalForAll,
//      permit, multicall, ...).
//   2. Read the target on-chain: is it an EOA or a contract? A proxy? New?
//   3. Turn every observation into a finding (info / warn / critical).
//   4. Score deterministically from 100: critical -60, warn -15, info 0.
//      Any critical finding blocks; otherwise SAFE >= 80, CAUTION 50-79,
//      BLOCK < 50.

const MAX_UINT256 = 2n ** 256n - 1n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// EIP-1967 storage slots.
const IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const BEACON_SLOT =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

// Free public JSON-RPC endpoints. Primary first, fallback second — no keys.
export const CHAINS = {
  1: {
    name: "Ethereum",
    rpcs: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"],
    blockTimeSec: 12,
    currency: "ETH",
  },
  8453: {
    name: "Base",
    rpcs: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
    blockTimeSec: 2,
    currency: "ETH",
  },
  84532: {
    name: "Base Sepolia",
    rpcs: [
      "https://sepolia.base.org",
      "https://base-sepolia-rpc.publicnode.com",
    ],
    blockTimeSec: 2,
    currency: "ETH",
  },
  10: {
    name: "Optimism",
    rpcs: [
      "https://mainnet.optimism.io",
      "https://optimism-rpc.publicnode.com",
    ],
    blockTimeSec: 2,
    currency: "ETH",
  },
  42161: {
    name: "Arbitrum One",
    rpcs: [
      "https://arb1.arbitrum.io/rpc",
      "https://arbitrum-one-rpc.publicnode.com",
    ],
    blockTimeSec: 2,
    currency: "ETH",
  },
};

// Function selectors we can decode (first 4 bytes of calldata).
const SELECTORS = {
  "0x095ea7b3": "approve",
  "0xa9059cbb": "transfer",
  "0x23b872dd": "transferFrom",
  "0xa22cb465": "setApprovalForAll",
  "0xd505accf": "permit",
  "0x42842e0e": "safeTransferFrom",
  "0xb88d4fde": "safeTransferFrom",
  "0xac9650d8": "multicall",
  "0xd0e30db0": "deposit", // WETH deposit()
  "0x2e1a7d4d": "withdraw", // WETH withdraw(uint256)
};

const TOKEN_FUNCTIONS = new Set([
  "approve",
  "transfer",
  "transferFrom",
  "permit",
]);

const CRITICAL_COST = 60;
const WARN_COST = 15;

export class ValidationError extends Error {}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function isAddress(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function isHexData(v) {
  return (
    typeof v === "string" &&
    /^0x([0-9a-fA-F]{2})*$/.test(v)
  );
}

function parseValue(v) {
  if (v === undefined || v === null || v === "") return 0n;
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) throw new ValidationError("value must be a non-negative integer (wei)");
    return BigInt(v);
  }
  if (typeof v === "string") {
    if (/^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v);
    if (/^[0-9]+$/.test(v)) return BigInt(v);
  }
  throw new ValidationError(
    "value must be a non-negative integer (wei) as a decimal or 0x-hex string"
  );
}

/** Format wei as a human-readable ETH string, e.g. 0.01, 1.5, 123. */
export function formatEth(wei) {
  const whole = wei / 10n ** 18n;
  const frac = wei % 10n ** 18n;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(18, "0").replace(/0+$/, "").slice(0, 6);
  return `${whole}.${fracStr}`;
}

function formatTokenAmount(amount, decimals, symbol) {
  if (decimals === null || decimals === undefined) {
    return `${amount.toString()} (raw units)`;
  }
  const scale = 10n ** BigInt(decimals);
  const whole = amount / scale;
  const frac = amount % scale;
  const fracStr = frac
    .toString()
    .padStart(decimals, "0")
    .replace(/0+$/, "")
    .slice(0, 4);
  const num = fracStr ? `${whole}.${fracStr}` : whole.toString();
  return symbol ? `${num} ${symbol}` : num;
}

function shortAddress(addr) {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

// ---------------------------------------------------------------------------
// JSON-RPC client (read-only, with per-chain fallback)
// ---------------------------------------------------------------------------

async function rpcCall(chain, method, params, timeoutMs = 8000) {
  let lastError = null;
  for (const url of chain.rpcs) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "Mozilla/5.0 (compatible; wildcard-guard/1.0)",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || "RPC error");
      return json.result;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError ?? new Error("all RPC endpoints failed");
}

// ---------------------------------------------------------------------------
// Calldata decoding
// ---------------------------------------------------------------------------

function wordAt(hex, i) {
  // hex: calldata without 0x. Returns the i-th 32-byte word as a hex string.
  const start = i * 64;
  if (hex.length < start + 64) return null;
  return hex.slice(start, start + 64);
}

function wordToAddress(word) {
  return `0x${word.slice(24)}`;
}

function wordToBigInt(word) {
  return BigInt(`0x${word}`);
}

/** Decode a multicall(bytes[]) payload into its inner calls (best effort). */
function parseMulticallInner(hex) {
  // Layout after the 4-byte selector: offset(32) | length(32) | offsets... | data...
  const calls = [];
  try {
    const lenWord = wordAt(hex, 1);
    if (!lenWord) return calls;
    const count = Number(wordToBigInt(lenWord));
    if (!Number.isSafeInteger(count) || count < 0 || count > 50) return calls;
    // Array data starts at byte offset 64 (offset word + length word).
    for (let i = 0; i < count; i++) {
      const offWord = wordAt(hex, 2 + i);
      if (!offWord) break;
      // Offsets are relative to the start of the array data (byte 64).
      const rel = Number(wordToBigInt(offWord));
      const absByte = 64 + rel;
      const absHex = absByte * 2;
      const lenHex = hex.slice(absHex, absHex + 64);
      if (lenHex.length < 64) break;
      const dataLen = Number(BigInt(`0x${lenHex}`));
      if (!Number.isSafeInteger(dataLen) || dataLen < 0 || dataLen > 100000) break;
      const dataHex = hex.slice(absHex + 64, absHex + 64 + dataLen * 2);
      if (dataHex.length < dataLen * 2) break;
      calls.push(`0x${dataHex}`);
    }
  } catch {
    // Malformed encoding — return what we have.
  }
  return calls;
}

/**
 * Decode calldata into { selector, name, args, truncated }.
 * args is null for unknown or truncated functions.
 */
function decodeCalldata(data) {
  const hex = data.slice(2); // strip 0x
  if (hex.length === 0) return { selector: null, name: null, args: null, truncated: false };
  const selector = `0x${hex.slice(0, 8)}`;
  const name = SELECTORS[selector] ?? null;
  const body = hex.slice(8);
  if (!name) return { selector, name: null, args: null, truncated: false };

  const need = (words) => body.length >= words * 64;
  try {
    switch (name) {
      case "approve":
      case "transfer": {
        if (!need(2)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: {
            spenderOrTo: wordToAddress(wordAt(body, 0)),
            amount: wordToBigInt(wordAt(body, 1)),
          },
          truncated: false,
        };
      }
      case "transferFrom": {
        if (!need(3)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: {
            from: wordToAddress(wordAt(body, 0)),
            to: wordToAddress(wordAt(body, 1)),
            amount: wordToBigInt(wordAt(body, 2)),
          },
          truncated: false,
        };
      }
      case "setApprovalForAll": {
        if (!need(2)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: {
            operator: wordToAddress(wordAt(body, 0)),
            approved: wordToBigInt(wordAt(body, 1)) !== 0n,
          },
          truncated: false,
        };
      }
      case "permit": {
        if (!need(7)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: {
            owner: wordToAddress(wordAt(body, 0)),
            spender: wordToAddress(wordAt(body, 1)),
            value: wordToBigInt(wordAt(body, 2)),
            deadline: wordToBigInt(wordAt(body, 3)),
          },
          truncated: false,
        };
      }
      case "safeTransferFrom": {
        if (!need(3)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: {
            from: wordToAddress(wordAt(body, 0)),
            to: wordToAddress(wordAt(body, 1)),
            tokenId: wordToBigInt(wordAt(body, 2)),
          },
          truncated: false,
        };
      }
      case "multicall": {
        return { selector, name, args: { inner: parseMulticallInner(body) }, truncated: false };
      }
      case "deposit": {
        return { selector, name, args: {}, truncated: false };
      }
      case "withdraw": {
        if (!need(1)) return { selector, name, args: null, truncated: true };
        return {
          selector,
          name,
          args: { amount: wordToBigInt(wordAt(body, 0)) },
          truncated: false,
        };
      }
      default:
        return { selector, name: null, args: null, truncated: false };
    }
  } catch {
    return { selector, name, args: null, truncated: true };
  }
}

// ---------------------------------------------------------------------------
// Token metadata (best effort, via eth_call)
// ---------------------------------------------------------------------------

function decodeAbiString(hex) {
  // hex: 0x-prefixed return data. Try ABI string, then bytes32.
  try {
    const body = hex.slice(2);
    if (body.length >= 128) {
      const len = Number(BigInt(`0x${body.slice(64, 128)}`));
      if (Number.isSafeInteger(len) && len > 0 && len <= 256) {
        const raw = body.slice(128, 128 + len * 2);
        const text = Buffer.from(raw, "hex").toString("utf8").replace(/\0/g, "");
        if (text) return text;
      }
    }
    // Fallback: bytes32 (e.g. MKR's symbol).
    const raw = Buffer.from(body.slice(0, 64), "hex").toString("utf8").replace(/\0/g, "");
    return raw || null;
  } catch {
    return null;
  }
}

async function fetchTokenMeta(chain, tokenAddress) {
  const calls = [
    { key: "symbol", data: "0x95d89b41" },
    { key: "decimals", data: "0x313ce567" },
    { key: "name", data: "0x06fdde03" },
  ];
  const results = await Promise.allSettled(
    calls.map((c) =>
      rpcCall(chain, "eth_call", [{ to: tokenAddress, data: c.data }, "latest"], 6000)
    )
  );
  const meta = { symbol: null, decimals: null, name: null };
  results.forEach((r, i) => {
    if (r.status !== "fulfilled" || !r.value || r.value === "0x") return;
    const key = calls[i].key;
    if (key === "decimals") {
      try {
        meta.decimals = Number(BigInt(r.value));
      } catch {
        /* ignore */
      }
    } else {
      meta[key] = decodeAbiString(r.value);
    }
  });
  return meta.symbol || meta.name || meta.decimals !== null ? meta : null;
}

// ---------------------------------------------------------------------------
// Main analysis
// ---------------------------------------------------------------------------

function validateInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ValidationError("request body must be a JSON object");
  }
  const chainId = Number(input.chainId);
  if (!Number.isInteger(chainId) || !CHAINS[chainId]) {
    throw new ValidationError(
      `unsupported chainId (supported: ${Object.keys(CHAINS).join(", ")})`
    );
  }
  if (!isAddress(input.to)) {
    throw new ValidationError("to must be a valid 0x address (40 hex chars)");
  }
  if (input.from !== undefined && input.from !== null && input.from !== "") {
    if (!isAddress(input.from)) {
      throw new ValidationError("from must be a valid 0x address (40 hex chars)");
    }
  }
  const data = input.data === undefined || input.data === null || input.data === ""
    ? "0x"
    : input.data;
  if (!isHexData(data)) {
    throw new ValidationError("data must be 0x-prefixed hex (even length)");
  }
  return {
    chainId,
    to: input.to,
    from: input.from || null,
    value: parseValue(input.value),
    data,
  };
}

/**
 * Analyze one transaction. Never throws for a well-formed request — on-chain
 * read failures degrade gracefully into "unknown" target info.
 */
export async function analyzeTransaction(input) {
  const startedAt = Date.now();
  const { chainId, to, from, value, data } = validateInput(input);
  const chain = CHAINS[chainId];
  const findings = [];
  const checksRun = [];
  const add = (severity, title, detail) =>
    findings.push({ severity, title, detail });

  const decoded = decodeCalldata(data);
  const hasCalldata = data !== "0x";

  // --- 1. Calldata findings -------------------------------------------------
  let tokenMeta = null;
  if (!hasCalldata && value === 0n) {
    add("info", "Empty transaction", "No native value and no calldata — signing this does nothing on-chain.");
  }
  if (decoded.truncated) {
    add("warn", "Truncated calldata", `The data starts with the ${decoded.name} selector but is missing arguments — this call would revert.`);
  } else if (decoded.name === "approve") {
    const { spenderOrTo: spender, amount } = decoded.args;
    if (spender.toLowerCase() === ZERO_ADDRESS) {
      add("warn", "Approval to the zero address", "Approving the zero address is almost certainly a mistake.");
    } else if (amount === MAX_UINT256) {
      add("critical", "Unlimited token allowance", `This approves ${shortAddress(spender)} to spend ALL of your tokens of this contract, forever, until you revoke it. Scam approvals almost always ask for the maximum.`);
    } else {
      add("info", "Token approval", `Approves ${shortAddress(spender)} to spend a limited amount of this token.`);
    }
  } else if (decoded.name === "setApprovalForAll") {
    const { operator, approved } = decoded.args;
    if (approved) {
      add("critical", "Approval for ALL tokens in a collection", `This gives ${shortAddress(operator)} control over EVERY token you own from this contract (all NFTs / all token IDs). A single malicious approval can drain a whole collection.`);
    } else {
      add("info", "Revoking collection approval", `This removes ${shortAddress(operator)}'s approval for all tokens in this collection. Revokes are safe.`);
    }
  } else if (decoded.name === "permit") {
    const { spender, value: permitValue, deadline } = decoded.args;
    if (permitValue === MAX_UINT256) {
      add("critical", "Unlimited permit allowance", `This permit signature would let ${shortAddress(spender)} spend ALL of your tokens of this contract. Permits are signatures, not transactions — they can be used by anyone holding them.`);
    }
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    const oneYear = 365n * 24n * 3600n;
    if (deadline > nowSec + oneYear) {
      add("warn", "Permit deadline very far in the future", `This permit stays valid until ${new Date(Number(deadline) * 1000).toISOString().slice(0, 10)} — a leaked or phished permit could be used for years.`);
    } else if (deadline < nowSec) {
      add("warn", "Permit already expired", "The permit deadline has passed, so this call would revert.");
    } else {
      add("info", "Permit signature", `Authorizes ${shortAddress(spender)} to spend tokens via signature until ${new Date(Number(deadline) * 1000).toISOString().slice(0, 10)}.`);
    }
  } else if (decoded.name === "transfer" || decoded.name === "transferFrom" || decoded.name === "safeTransferFrom") {
    const recipient = decoded.args.to ?? decoded.args.spenderOrTo;
    if (recipient && recipient.toLowerCase() === ZERO_ADDRESS) {
      add("warn", "Transfer to the zero address", "Tokens sent to the zero address are burned and can never be recovered.");
    } else {
      add("info", "Token transfer", `Moves tokens to ${shortAddress(recipient)}.`);
    }
  } else if (decoded.name === "multicall") {
    const inner = decoded.args.inner;
    if (inner.length === 0) {
      add("warn", "Multicall with unreadable inner calls", "This bundles several calls, but the inner calls could not be decoded — review the raw data before signing.");
    } else {
      const innerNames = inner.map((c) => {
        const d = decodeCalldata(c);
        return d.name ?? d.selector ?? "empty";
      });
      let nestedDanger = false;
      for (const c of inner) {
        const d = decodeCalldata(c);
        if (d.name === "approve" && d.args && d.args.amount === MAX_UINT256) {
          add("critical", "Unlimited approval hidden inside multicall", "One of the batched calls approves the maximum token amount. Bundled calls are a common way to hide a malicious approval.");
          nestedDanger = true;
        }
        if (d.name === "setApprovalForAll" && d.args && d.args.approved) {
          add("critical", "Approval-for-all hidden inside multicall", "One of the batched calls grants approval for an entire token collection.");
          nestedDanger = true;
        }
      }
      if (!nestedDanger) {
        if (innerNames.some((n) => n.startsWith("0x"))) {
          add("warn", "Multicall contains unknown inner calls", `Batched calls: ${innerNames.join(", ")}. At least one inner call could not be identified — review before signing.`);
        } else {
          add("info", "Batched calls", `Multicall with ${inner.length} inner call(s): ${innerNames.join(", ")}.`);
        }
      }
    }
  } else if (decoded.name === "deposit" || decoded.name === "withdraw") {
    add("info", `WETH ${decoded.name}`, "A standard wrapped-ETH wrap/unwrap call.");
  } else if (hasCalldata && decoded.selector) {
    add("warn", `Unknown function (${decoded.selector})`, "This function is not in the guard's known list, so what the call does cannot be verified from the calldata alone. Never blind-sign an unknown function on an unfamiliar contract.");
  }

  // Value + unknown function is riskier than either alone.
  if (value > 0n && hasCalldata && !decoded.name) {
    add("warn", "Native value sent with an unverified call", `${formatEth(value)} ${chain.currency} would go to the target along with a call whose effect cannot be verified.`);
  }

  // --- 2. On-chain target checks (best effort, parallel) --------------------
  let targetType = "unknown";
  let implementation = null;
  let isBeacon = false;
  let youngContract = null;

  const needsTokenMeta = TOKEN_FUNCTIONS.has(decoded.name);
  const [codeResult, blockResult, metaResult] = await Promise.allSettled([
    rpcCall(chain, "eth_getCode", [to, "latest"]),
    rpcCall(chain, "eth_blockNumber", []),
    needsTokenMeta ? fetchTokenMeta(chain, to) : Promise.resolve(null),
  ]);
  checksRun.push("target-code");
  if (needsTokenMeta) checksRun.push("token-metadata");

  if (codeResult.status === "fulfilled") {
    const code = codeResult.value;
    if (code === "0x") {
      targetType = "eoa";
    } else if (
      typeof code === "string" &&
      code.toLowerCase().startsWith("0xef0100") &&
      code.length === 2 + 46 // EIP-7702 delegation designator + 20-byte address
    ) {
      // EIP-7702: an EOA that delegated its code to a smart account.
      targetType = "eoa";
      add(
        "info",
        "EOA with EIP-7702 delegation",
        `This wallet delegates its code to smart account ${shortAddress(`0x${code.slice(8)}`)} (EIP-7702). The account behaves like a smart wallet while the delegation is active.`
      );
    } else {
      targetType = "contract";
    }
  } else {
    add("info", "Target lookup unavailable", "The public RPC did not answer the code check, so the target type could not be confirmed. The calldata findings above still apply.");
  }

  if (metaResult.status === "fulfilled" && metaResult.value) {
    tokenMeta = metaResult.value;
    // Enrich the approval finding with the real token symbol/amount.
    if (decoded.name === "approve" && decoded.args) {
      const amt = formatTokenAmount(decoded.args.amount, tokenMeta.decimals, tokenMeta.symbol);
      const f = findings.find((x) => x.title.includes("allowance") || x.title === "Token approval");
      if (f && decoded.args.amount !== MAX_UINT256) {
        f.detail = `Approves ${shortAddress(decoded.args.spenderOrTo)} to spend ${amt}.`;
      }
    }
    if (decoded.name === "permit" && decoded.args) {
      const amt = formatTokenAmount(decoded.args.value, tokenMeta.decimals, tokenMeta.symbol);
      const f = findings.find((x) => x.title === "Permit signature");
      if (f) f.detail = `Authorizes ${shortAddress(decoded.args.spender)} to spend ${amt} via signature.`;
    }
  }

  if (to.toLowerCase() === ZERO_ADDRESS) {
    add("warn", "Target is the zero address", "Any native value sent to the zero address is lost forever.");
  }

  if (targetType === "eoa") {
    if (hasCalldata) {
      add("warn", "Calldata sent to a plain wallet address", "The target has no code, so the calldata would do nothing — this usually means a wrong address, or a transaction crafted to look like something it is not.");
    } else if (value > 0n) {
      if (value >= 10n ** 18n) {
        add("warn", "Large native transfer to a wallet", `${formatEth(value)} ${chain.currency} to an externally owned account. Double-check the address — native transfers cannot be reversed.`);
      } else {
        add("info", "Plain native transfer", `${formatEth(value)} ${chain.currency} to a wallet address.`);
      }
    }
  }

  if (targetType === "contract") {
    add("info", "Target is a smart contract", "The destination address has code deployed.");
    if (value > 0n && decoded.name) {
      add("info", "Native value sent with the call", `${formatEth(value)} ${chain.currency} is sent to the contract along with this call.`);
    }

    // Proxy + age checks, in parallel.
    const oldBlock =
      blockResult.status === "fulfilled"
        ? (() => {
            const current = BigInt(blockResult.value);
            const blocks30d = (30n * 24n * 3600n) / BigInt(chain.blockTimeSec);
            return current > blocks30d ? current - blocks30d : 0n;
          })()
        : null;
    const [implResult, beaconResult, oldCodeResult] = await Promise.allSettled([
      rpcCall(chain, "eth_getStorageAt", [to, IMPLEMENTATION_SLOT, "latest"]),
      rpcCall(chain, "eth_getStorageAt", [to, BEACON_SLOT, "latest"]),
      oldBlock
        ? rpcCall(chain, "eth_getCode", [to, `0x${oldBlock.toString(16)}`])
        : Promise.resolve(null),
    ]);
    checksRun.push("proxy-slots", "contract-age");

    if (implResult.status === "fulfilled" && implResult.value) {
      const slot = implResult.value;
      if (slot !== "0x" + "0".repeat(64)) {
        implementation = `0x${slot.slice(-40)}`;
        add("warn", "Upgradeable proxy contract", `Logic lives at implementation ${shortAddress(implementation)} and can be changed by the proxy admin. What the contract does today may not be what it does tomorrow.`);
      }
    }
    if (beaconResult.status === "fulfilled" && beaconResult.value) {
      const slot = beaconResult.value;
      if (slot !== "0x" + "0".repeat(64)) {
        isBeacon = true;
        add("warn", "Beacon proxy contract", "Logic is resolved through a beacon and can be changed for every proxy using it at once.");
      }
    }
    if (oldCodeResult.status === "fulfilled" && oldCodeResult.value !== null) {
      youngContract = oldCodeResult.value === "0x";
      if (youngContract) {
        add("warn", "Very new contract", "This contract did not exist ~30 days ago. New contracts carry higher risk — established scams often deploy fresh contracts for each wave.");
      }
    }
  }

  if (from && from.toLowerCase() === to.toLowerCase()) {
    add("info", "Self-transfer", "The sender and recipient are the same address.");
  }

  // --- 3. Score + verdict ---------------------------------------------------
  let score = 100;
  let criticals = 0;
  for (const f of findings) {
    if (f.severity === "critical") {
      score -= CRITICAL_COST;
      criticals++;
    } else if (f.severity === "warn") {
      score -= WARN_COST;
    }
  }
  score = Math.max(0, Math.min(100, score));

  let verdict;
  if (criticals > 0 || score < 50) verdict = "BLOCK";
  else if (score < 80) verdict = "CAUTION";
  else verdict = "SAFE";

  const topCritical = findings.find((f) => f.severity === "critical");
  const topWarn = findings.find((f) => f.severity === "warn");
  let summary;
  if (verdict === "BLOCK") {
    summary = topCritical
      ? `Blocked: ${topCritical.title}. Do not sign this transaction.`
      : "Blocked: multiple high-risk signals. Do not sign this transaction.";
  } else if (verdict === "CAUTION") {
    summary = topWarn
      ? `Proceed with caution: ${topWarn.title}.`
      : "Proceed with caution: some risk signals found.";
  } else if (topWarn) {
    summary = `Looks safe, with ${findings.filter((f) => f.severity === "warn").length} warning(s) to review before signing.`;
  } else if (!hasCalldata && value > 0n) {
    summary = `Looks safe: a plain ${formatEth(value)} ${chain.currency} transfer.`;
  } else if (decoded.name) {
    summary = `Looks safe: recognized ${decoded.name} call with no dangerous permissions.`;
  } else {
    summary = "Looks safe: no dangerous permissions detected.";
  }

  return {
    verdict,
    score,
    summary,
    chainId,
    chainName: chain.name,
    to,
    from,
    value: value.toString(),
    valueEth: formatEth(value),
    currency: chain.currency,
    function: decoded.name
      ? { name: decoded.name, selector: decoded.selector }
      : decoded.selector
        ? { name: null, selector: decoded.selector }
        : null,
    target: {
      type: targetType,
      proxy: implementation !== null || isBeacon,
      implementation,
      youngContract,
    },
    token: tokenMeta,
    findings,
    checksRun,
    durationMs: Date.now() - startedAt,
  };
}
