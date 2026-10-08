# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately (GitHub "Report a vulnerability" on this
repository, or contact the maintainer directly) rather than opening a public issue. Include
reproduction steps and the affected version. There is no bug bounty.

## Trust model and what Ledger does NOT protect against

Ledger is an integrity tool with a narrow, explicit trust boundary.

* **On-chain anchoring proves existence and non-tampering of a hash after a point in time.**
  It does not prove the underlying data was captured correctly or is true.
* **The anchoring key is the trust boundary.** The contract only accepts batches from
  allowlisted addresses. A batch proves that *this key* anchored *this root at this time*; it
  does not prove the key belongs to the real Aegis or Gauntlet instance. If the anchoring key
  is stolen, an attacker can anchor roots for fabricated data. Production deployments should
  add a signed attestation from Aegis's own key before anchoring (see Roadmap in the README).
* **Garbage in, garbage out.** If a compromised Aegis database is collected *before* anchoring,
  Ledger anchors the forged data faithfully. Anchoring only detects changes made *afterwards*.
* **The local chain is a development chain.** Anvil is a single node: whoever controls it can
  rewrite history. For real tamper-evidence the root must be anchored on a chain whose history
  you do not control (a public testnet or L2). The default local setup demonstrates the
  mechanism, not independent consensus.

## Operational guidance

* The default keys are Anvil's public development keys. Ledger **refuses** to use them against
  a non-local RPC URL. Never put real funds or mainnet keys in this tool's config.
* The HTTP API has no user accounts. Bind it to localhost (the compose file does) or put it
  behind your own authentication. Set `api_key` to require `X-Ledger-Key` on mutating endpoints.
* The API never accepts database URLs or arbitrary file paths from callers: Aegis collection
  uses the server-side `aegis_db_url`, and Gauntlet results must be inside `inbox_dir`.
* Collectors are read-only against Aegis (use a read-only database role) and never store
  prompt snippets or raw attack text; only hashes and short metadata enter the index.

## Responsible use

Ledger is for protecting the integrity of your own audit logs and security reports. Do not
use it to timestamp data you are not entitled to process. Gauntlet findings can describe real
weaknesses: treat the index and cached source copies as sensitive.
