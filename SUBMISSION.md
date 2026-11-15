# SignGuard — Agent Games Wildcard Submission Draft

## Agent name
SignGuard — Wallet & Transaction Guard

## Use case
Every day, crypto users lose funds not to hacks of their wallets, but to
transactions they approved themselves: an unlimited token allowance to a
scam contract, a setApprovalForAll that hands over an entire NFT collection,
a permit signature, or an approval hidden inside a multicall. Wallets show
hex calldata and ask "sign?" — most users cannot read it, so they trust the
site in front of them. Approval phishing alone has drained billions.

SignGuard helps anyone with an EVM wallet — especially newcomers and
airdrop/testnet users who touch many unknown contracts — by screening a
transaction BEFORE it is signed. Paste the transaction (chain, target,
value, calldata) and SignGuard returns a plain-language verdict — SAFE,
CAUTION, or BLOCK — with a score and a finding for every risk it detected,
so the user can make an informed decision instead of a blind one.

## Build context
SignGuard is a zero-dependency Node.js agent (stdlib HTTP + fetch, no API
keys, no secrets). For each transaction it:
- Decodes the calldata and recognizes common selectors (approve, transfer,
  setApprovalForAll, permit, multicall — including approvals nested inside
  multicalls) and flags unlimited allowances and collection-wide approvals.
- Reads the target on-chain via free public JSON-RPC (Ethereum, Base, Base
  Sepolia, Optimism, Arbitrum): is it an EOA or a contract, is it a proxy
  (EIP-1967 implementation / beacon slots), how old is it, and what token
  it is (symbol/decimals/name via eth_call).
- Recognizes EIP-7702 delegated EOAs so modern smart wallets are not
  mislabelled as contracts.
- Scores deterministically (start 100; critical findings −60, warnings −15;
  any critical finding means BLOCK).

Key decisions: read-only by design — the agent never connects a wallet,
never signs, and never holds keys; no paid services or API keys so anyone
can run it; a one-page demo UI with one-click examples so judges can see a
BLOCK verdict in seconds. Honest limits: static analysis plus on-chain
reads only — no execution simulation and no scam-address blocklist, so it
cannot see what a contract does internally.

## Agent link (to fill in)
Public repo: <GitHub repo URL — pending user's GitHub account>
Demo: <public endpoint URL — pending deploy>

## Public endpoint (to fill in)
<https://… — Render deploy once GitHub exists; cloudflared quick tunnel
does NOT work from this VM (egress proxy blocks cloudflared's TLS)>

## zkVerify (optional)
Not used. SignGuard's claims are checkable a different way: every finding
names the on-chain read behind it (target bytecode, storage slot, token
metadata), so anyone can re-verify a verdict against a public RPC.
