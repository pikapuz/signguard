# Wildcard Guard — check a transaction before you sign it

An Agent Games (Wildcard track) entry: a wallet & transaction guard that
screens EVM approvals and transactions for scams and risky permissions
**before** the user signs.

## The problem

Most wallet losses do not come from broken cryptography — they come from
blind signing. A user is shown a hex blob, clicks "confirm", and only later
discovers they approved an unlimited token allowance, handed over an entire
NFT collection with `setApprovalForAll`, or signed a permit that a scammer
can redeem for years. By the time the drain is visible, the funds are gone.

## Who it helps

Anyone with a crypto wallet — especially newcomers and airdrop/testnet users
who interact with unfamiliar contracts every day. The guard speaks plain
language: what the transaction does, what permission it grants, and whether
it is safe to sign.

## What it does

Send a transaction (chain, destination, value, calldata) and the guard
returns a verdict — `SAFE`, `CAUTION`, or `BLOCK` — with a 0–100 score and
a list of findings, each with a severity and a plain-language explanation.

It runs as a small HTTP server with a demo UI and a JSON API. No wallet
connection, no signing, no private keys anywhere: the guard only performs
read-only JSON-RPC calls against free public endpoints.

Supported chains: Ethereum (1), Base (8453), Base Sepolia (84532),
Optimism (10), Arbitrum One (42161).

## How each check works

| Check | What it does | Severity |
|---|---|---|
| Unlimited allowance | Decodes `approve(spender, amount)`; amount == `type(uint256).max` is the classic drain setup. | critical |
| Approval for all | `setApprovalForAll(operator, true)` hands over every token in a collection. `false` (revoke) is safe. | critical |
| Permit abuse | Decodes `permit(...)`; max value is critical, a deadline more than a year out (or already passed) is a warning. | critical / warn |
| Hidden approvals | Decodes `multicall(bytes[])` inner calls and flags unlimited approvals or approval-for-all buried inside the batch. | critical |
| Unknown function | Calldata whose 4-byte selector is not recognized is flagged, never trusted. | warn |
| Value + unknown call | Native value sent together with an unverified function call is riskier than either alone. | warn |
| Calldata to an EOA | Calldata sent to an address with no code does nothing — usually a wrong address or a crafted transaction. | warn |
| Large native transfer | ≥ 1 ETH to a plain wallet address — irreversible, double-check the address. | warn |
| Zero address | Transfers/approvals to `0x000…000`, or a zero-address target. | warn |
| Target type | EOA vs contract via `eth_getCode`. EIP-7702 delegated EOAs (code `0xef0100…`) are recognized and reported as wallets, not contracts. | info |
| Upgradeable proxy | Reads the EIP-1967 implementation and beacon slots; proxied logic can change after you sign. | warn |
| Contract age | Compares `eth_getCode` now vs ~30 days ago; contracts that did not exist a month ago are flagged. | warn |
| Token metadata | `eth_call` for `symbol()`/`decimals()`/`name()` so findings name the real token (e.g. "1,000 USDC"). | info |

Scoring is deterministic: every transaction starts at 100. A critical
finding costs 60 points, a warning 15, info costs nothing. Any critical
finding blocks. Verdicts: **SAFE** ≥ 80, **CAUTION** 50–79, **BLOCK** < 50
(or any critical finding).

## Run it

```bash
npm install   # no dependencies — this just verifies the install
npm start     # listens on http://localhost:3000 (override with PORT)
```

Requires Node.js 18+. Zero runtime dependencies — standard library only.

## Try it

Open http://localhost:3000 — the demo page has one-click examples:

1. **Safe transfer** — 0.01 ETH to a plain wallet → SAFE.
2. **Unlimited approval** — `approve(spender, max)` on USDC → BLOCK.
3. **Approval for all NFTs** — `setApprovalForAll(true)` on BAYC → BLOCK.
4. **Suspicious unknown call** — 1 ETH + unknown function to a contract → CAUTION.
5. **Permit, far-future deadline** — permit valid until 2100 → SAFE with a warning.

## API

### `GET /health`

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

### `POST /api/guard`

```bash
curl -X POST http://localhost:3000/api/guard \
  -H "Content-Type: application/json" \
  -d '{"chainId":1,"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0","data":"0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'
```

Expected output (abridged):

```json
{
  "verdict": "BLOCK",
  "score": 40,
  "summary": "Blocked: Unlimited token allowance. Do not sign this transaction.",
  "chainId": 1,
  "chainName": "Ethereum",
  "function": { "name": "approve", "selector": "0x095ea7b3" },
  "target": { "type": "contract", "proxy": false, "implementation": null, "youngContract": false },
  "token": { "symbol": "USDC", "decimals": 6, "name": "USD Coin" },
  "findings": [
    { "severity": "critical", "title": "Unlimited token allowance",
      "detail": "This approves 0x1111…1111 to spend ALL of your tokens of this contract, forever, until you revoke it. ..." },
    { "severity": "info", "title": "Target is a smart contract", "detail": "..." }
  ],
  "checksRun": ["target-code", "token-metadata", "proxy-slots", "contract-age"],
  "durationMs": 1234
}
```

A plain transfer:

```bash
curl -X POST http://localhost:3000/api/guard \
  -H "Content-Type: application/json" \
  -d '{"chainId":1,"to":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","value":"10000000000000000","data":"0x"}'
# -> {"verdict":"SAFE","score":100,"summary":"Looks safe: a plain 0.01 ETH transfer.", ...}
```

Malformed input returns a clean `400` with a message, never a crash:

```bash
curl -X POST http://localhost:3000/api/guard \
  -H "Content-Type: application/json" \
  -d '{"chainId":1,"to":"not-an-address","value":"0","data":"0x"}'
# -> {"error":"to must be a valid 0x address (40 hex chars)"}
```

Response fields: `verdict`, `score`, `summary`, `chainId`, `chainName`,
`to`, `from`, `value` (wei, string), `valueEth`, `currency`, `function`
(decoded name/selector or null), `target` (type, proxy, implementation,
youngContract), `token` (symbol/decimals/name or null), `findings`
(`severity`, `title`, `detail`), `checksRun`, `durationMs`.

## Honest limits

- **Static + on-chain-read checks only.** The guard reads code, storage
  slots, and calldata — it does not simulate execution, so it cannot see
  what a contract does internally (e.g. a `delegatecall` to a malicious
  implementation, or a token that blocks sells).
- **No reputation data.** There is no blocklist of known scam addresses;
  everything is derived from the transaction itself and public chain state.
- **No explorer APIs.** Contract age is a best-effort heuristic from
  `eth_getCode` at a past block; it can be skipped silently if the RPC
  cannot serve historical state.
- **Heuristics, not proof.** A SAFE verdict means "no dangerous permission
  detected", not "this contract is trustworthy". A new contract doing a
  plain transfer can still be part of a scam.
- **Not financial advice.** The guard is a second pair of eyes, not a
  guarantee. When in doubt, do not sign.

## Files

- `server.js` — HTTP server: demo UI (`/`), health (`/health`), API (`POST /api/guard`).
- `guard.js` — the analysis: calldata decoding, RPC reads, checks, scoring.
- `public/index.html` — the single-page demo UI.
- `package.json` — zero-dependency Node.js package.
