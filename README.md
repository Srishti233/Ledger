# Ledger

[![CI](https://github.com/Srishti233/Ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/Srishti233/Ledger/actions/workflows/ci.yml)

**Tamper-evident proof for your security logs, without trusting any single server.** Ledger takes the hash-chained audit log kept by [Aegis](#relationship-to-aegis-and-gauntlet) (an LLM firewall) and the vulnerability reports produced by [Gauntlet](#relationship-to-aegis-and-gauntlet) (a red-teaming framework), batches their hashes into Merkle trees, and writes only the 32-byte root to a smart contract on a blockchain. Later, anyone can check that a record existed at a given time and has not been edited since, against the chain itself rather than against Ledger's database, Aegis's database, or any one machine. It runs end to end on a free, local, self-hosted chain (Anvil): no paid APIs, no real funds, no accounts.

> **Project 3 of 3.** Aegis blocks attacks and keeps a tamper-evident log. Gauntlet finds what gets through. Ledger proves neither record was quietly edited after the fact.

## What this proves, and what it does not

**Anchoring a hash on-chain proves:** (a) this exact hash existed no later than block N, with a timestamp derived from that block, and (b) nobody can alter the anchored hash after the fact without the alteration being obvious, because changing one historical block would break the chain's own hash-linking, which is independently checkable by anyone running a node.

**It does NOT prove:** that the underlying data (an Aegis audit row, a Gauntlet report) was captured correctly; that Ledger itself did not anchor a wrong hash to begin with; that the anchoring key belongs to the real Aegis or Gauntlet instance; or anything about the real-world truth of what the log claims happened. Ledger's verification reports state this limitation explicitly every time.

Two further honest caveats: the default local chain is a single dev node, so whoever controls it can rewrite history (it demonstrates the mechanism; for independent consensus, anchor to a public testnet/L2, see [Roadmap](#roadmap)); and the contract only accepts batches from an owner-managed allowlist of keys (see [Limitations](#limitations)).

## Architecture

```mermaid
flowchart TD
    A[Aegis audit_events table] -->|read-only| C[collector]
    G[Gauntlet results.json] --> C
    S[synthetic fixtures] --> C
    C -->|canonical record, leaf hash| I[(local SQLite index<br/>leaf → batch → tx → block)]
    I --> B[batcher: Merkle tree]
    B -->|root only| K[AuditAnchor contract<br/>local Anvil chain]
    K -->|BatchAnchored event, tx, block| I
    I --> V[verifier]
    K -->|live getBatch| V
    A -. re-fetch source data .-> V
    V --> R[human report + JSON verdict]
```

The verifier treats **only the on-chain root as trusted**. Everything Ledger stored locally (leaves, proofs, roots) and the source data are re-checked against it, which is what distinguishes a compromised Ledger database from a compromised Aegis database.

## Quick start

```bash
git clone https://github.com/Srishti233/Ledger.git && cd Ledger
docker compose up --build -d          # Anvil chain + Ledger service (deploys the contract automatically)
bash scripts/demo.sh                  # collect → anchor → verify → tamper → detect
```

> **About the private keys in this repo.** `config.py`, `config.example.yaml` and `Deploy.s.sol` contain two `0x...` private keys. They are Anvil's **public development keys** (the same on every developer's machine, documented by Foundry) and control only worthless test ETH on a local chain. A secret scanner may flag them; that is a false positive. Ledger refuses to use them against any non-local RPC URL.

Dashboard: <http://127.0.0.1:8000/dashboard>. The first build downloads the Foundry image and, once, the Solidity compiler. Reset everything (chain and index must be reset together) with `make reset`.

Without Docker: `pip install -e ".[dev]"`, `anvil &`, `(cd contracts && forge build)`, then `ledger deploy && ledger demo`.

## The tamper-detection demo

`bash scripts/demo.sh` runs `ledger demo` against the real chain and fails unless all of these hold:

1. A batch of synthetic records is collected and anchored; the real transaction hash and gas used are printed.
2. The clean batch verifies, including with the full source record set supplied.
3. **Ledger's own SQLite index is edited directly**, with a recomputed leaf so the row looks self-consistent, simulating a compromised Ledger server. Verification **fails**, names the exact record, and diagnoses `LEDGER_INDEX_MODIFIED`. The row is then restored and verifies again.
4. **A copy of the Aegis audit-table fixture is edited**, simulating a compromised Aegis database. Verification with the full record set **fails for a different, correctly labelled reason**: the index and on-chain root are intact (`recomputed_root_equals_chain_root` passes) but the leaf recomputed from the modified source no longer matches (`SOURCE_DATA_MODIFIED`).
5. A plain-English summary distinguishes what each result proves.

How the two cases are told apart: each record's stored Merkle proof is checked against the **live on-chain root**. A forged index row cannot produce a valid proof for the on-chain root (that would require a SHA-256 preimage), so it fails; a modified source row fails because its fresh hash does not verify through the *untouched* index proof.

Real output from the CI `demo` job (2026-10-08, a fresh Anvil chain; lines trimmed with `...`, nothing edited):

```text
Ledger demo: chain connected=True contract=0x5FbDB2315678afecb367f032d93F642f64180aa3

[2/6] Build a Merkle tree and anchor its root on-chain.
  tx hash   : 0x5ea414db12e1aa7ba92a37161b540dd468d30aa4a3f981819d37a7ce842aa95e
  block     : 3
  gas used  : 140178
  root      : 7cb56443292dfecbc9fe1618b3e7fbdb02297b9d85c04827f95881f9b7ea6022
  records   : 25
  took      : 0.133s

[3/6] Verify the batch (index vs live chain).
== batch 1: VERIFIED ==
  [ok]   index_root_equals_chain_root: roots match
  [ok]   recomputed_root_equals_chain_root: root recomputed from the indexed leaves equals the on-chain root
  [ok]   every_record_included_in_onchain_root: all 25 stored leaves + proofs reproduce the on-chain root
  [skip] source_full_record_set: full record set not supplied
  What was proven:
    + the anchored leaf is included in Merkle root 7cb56443292dfecb..., which was written on-chain in block 3 at 2026-10-08T04:33:51+00:00 by 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; this exact hash therefore existed no later than then.

[4/6] TAMPER with Ledger's own SQLite index (record 13, 13) -- simulating a compromised Ledger server.
== batch 1: TAMPER DETECTED ==
  [ok]   index_root_equals_chain_root: roots match
  [ok]   record_set_complete: 25 records at positions 0..24, chain says 25
  [FAIL] recomputed_root_equals_chain_root: recomputed 57dff4c0cc008505... vs on-chain 7cb56443292dfecb...
  [FAIL] every_record_included_in_onchain_root: 1 record(s) fail their stored leaf/proof against the chain
  Diagnosis:
    - LEDGER_INDEX_MODIFIED: Ledger's local index no longer matches what was anchored on-chain (simulates a compromised Ledger server). The chain, not the index, is authoritative.
  Records whose index entry fails against the chain: [13]
  What was NOT proven / not checked:
    - whether the original data was captured correctly or is true in the real world.
    - that the anchoring key belongs to the real Aegis/Gauntlet instance.
  -> PASS: report identifies exactly the tampered record (culprits=[13])

[5/6] TAMPER with a COPY of the Aegis audit table fixture (row id 13) -- simulating a compromised Aegis database; verify with the full record set supplied.
== batch 1: TAMPER DETECTED ==
  [ok]   recomputed_root_equals_chain_root: root recomputed from the indexed leaves equals the on-chain root
  [ok]   every_record_included_in_onchain_root: all 25 stored leaves + proofs reproduce the on-chain root
  [FAIL] source_full_record_set: 1 record(s) recomputed from source no longer match the anchor
  Diagnosis:
    - SOURCE_DATA_MODIFIED: The source data no longer hashes to the leaf that was anchored: the source (e.g. the Aegis audit table) was changed after anchoring. The on-chain root is intact.
  Records whose source data no longer matches the anchor: [13]
  -> PASS: report identifies exactly the tampered source row (culprits=[13])

DEMO PASSED: 10/10 expectations met
```

The contract address is Anvil's deterministic first-deployment address and `0x7099...79C8` is Anvil's public test account #1; both are well known and hold nothing of value. Note the two tamper cases: in step 4 the on-chain-root comparison fails, while in step 5 it passes and only the source check fails, which is how Ledger tells a compromised Ledger database from a compromised Aegis database.

## Evaluation (measured)

Produced by `make eval` inside the CI `demo` job: a GitHub Actions Ubuntu runner (Python 3.12) running the full Docker stack with a **real Anvil chain**, on 2026-10-08. Committed as [`results/eval.json`](results/eval.json) and [`results/eval.md`](results/eval.md). This is a single run on one machine type; the timings are medians of a few repetitions within that run (500 for proof verification, 5 for record verification, 3 for batch verification), so read them as indicative, not as a benchmark.

| records in batch | gas used | anchor time (s) | inclusion-proof verify (ms) | record verify, incl. chain query (ms) | batch verify, incl. chain query (ms) |
|---:|---:|---:|---:|---:|---:|
| 1 | 123,078 | 0.129 | 0.0006 | 8.1 | 8.0 |
| 10 | 123,078 | 0.126 | 0.0036 | 7.8 | 8.1 |
| 100 | 123,078 | 0.131 | 0.0062 | 8.3 | 10.9 |
| 1000 | 123,090 | 0.170 | 0.0149 | 10.9 | 50.8 |

**Headline: the on-chain cost does not grow with the batch.** Anchoring 1 record or 100 records costs the same 123,078 gas; 1000 records costs 12 gas more. That 12 is exactly the extra calldata cost of one more non-zero byte in the `recordCount` argument (1000 needs two non-zero bytes, the others one; 16 - 4 = 12 gas). Because only the 32-byte root is stored, anchoring 1000 records individually would cost roughly 1000 x 123,078, about 123 million gas (arithmetic from the one-record row, not a separate measurement), versus 123,090 for one batch.

Other observations from this run: anchoring (transaction, receipt and confirmation wait) took about 0.13 s on the local chain; every verdict was `verified`; verifying a single inclusion proof is a few microseconds of pure hashing; the live-chain checks dominate the cost of a record verification (about 8 ms); and a 1000-record batch verifies in about 51 ms, because it recomputes the root and checks every stored proof.

**First call on a fresh contract costs more.** The demo's first-ever anchor on a brand-new contract used 140,178 gas (25 records, block 3), while later calls in the same CI run used 123,078 (the table above, and the 5-record API smoke test in the demo job, which reported 123,078 total). The difference is exactly 17,100 gas, which equals the cost of writing a storage slot for the first time (22,100) minus updating an existing one (5,000): the first `anchorBatch` also initialises the contract's batch counter. It is a one-time cost per contract. `make eval` therefore sends a throwaway warm-up anchor first and excludes it from the table (123,030 gas in that run, which was not a first call because the demo had already used the contract), and the Foundry and integration gas tests warm up before comparing.

**Illustrative cost per batch** (assumed gas prices, not a live feed; no price API is called, and these are not measurements): at an assumed 20 gwei on Ethereum L1, 123,078 gas is about 0.00246 ETH; at an assumed 0.05 gwei on a typical rollup L2, about 0.0000062 ETH; on a free public testnet, nothing of value. The assumptions are editable constants in `ledger/evaluation.py`.

**Pure-Python Merkle timings** (same run, no chain): building a 1000-leaf tree takes about 1.3 ms; generating or verifying one proof takes under 0.01 ms; a proof for 1000 leaves has 10 steps.

| records | tree build (ms) | proof generate (ms) | proof verify (ms) | proof length |
|---:|---:|---:|---:|---:|
| 1 | 0.001 | 0.0007 | 0.0012 | 0 |
| 10 | 0.022 | 0.0051 | 0.0067 | 4 |
| 100 | 0.181 | 0.0083 | 0.0107 | 7 |
| 1000 | 1.297 | 0.0063 | 0.0081 | 10 |

Reproduce: `docker compose up --build -d && make eval`.

## CLI reference

`ledger [--config FILE] <command>` (config: YAML plus `LEDGER_*` env overrides, see `config.example.yaml`).

| command | purpose |
|---|---|
| `deploy` | Deploy `AuditAnchor` (or reuse it) and allowlist the anchoring key. Archives a stale index if the local chain was reset. |
| `collect-aegis [--db-url URL] [--limit N]` | Read new `audit_events` rows read-only (Postgres or `sqlite:///file`). Only `id, timestamp, direction, decision, entry_hash` are kept; never the snippet. Exits 3 if Aegis is unreachable. |
| `collect-gauntlet --results results.json [--bypass-key K]` | Hash the whole file plus each bypass finding (`attack_id`, `target_name`, SHA-256 of `variant_text`). Exits 3 if missing. |
| `collect-synthetic [--count N] [--kind aegis\|gauntlet]` | Generate fixture records tagged `source=synthetic`. |
| `anchor-now` | Anchor all pending records (one batch per source, chunked by `batch_size`). |
| `verify --record ID \| --batch ID [--records FILE] [--full] [--no-source] [--json] [--json-out FILE]` | Verify against the live chain. Exit codes: **0** verified, **1** tamper detected, **2** inconclusive (e.g. chain unreachable, which is never reported as a pass). |
| `status`, `record ID`, `proof ID`, `batch [ID]` | Inspect state; `proof` output can be checked offline. |
| `serve [--host --port]` | HTTP API and dashboard. |
| `demo [--count N]` | The tamper-detection walkthrough above. |
| `eval [--sizes 1,10,100,1000] [--out DIR] [--merkle-only]` | Measured evaluation. |

## HTTP API reference

| endpoint | notes |
|---|---|
| `POST /collect/aegis` | Uses the server-side `aegis_db_url` only. The API never accepts a DB URL from callers. |
| `POST /collect/gauntlet` `{"results_path": "results.json"}` | Path must resolve inside `inbox_dir` (default `<data_dir>/inbox`). |
| `POST /collect/synthetic` `{"count": 25, "kind": "aegis"}` | |
| `POST /anchor-now` | Anchors everything pending. |
| `GET /records/{id}`, `GET /records/{id}/proof` | Record, batch, and Merkle proof. |
| `GET /verify/{id}?use_source=true`, `GET /verify/batch/{id}?full=false` | Verdict JSON (always HTTP 200; read `status`). |
| `GET /batches`, `GET /batches/{id}`, `GET /status`, `GET /health` | |
| `GET /metrics` | Prometheus: records collected/anchored/pending, batches, gas spent, anchor latency. |
| `GET /dashboard` | Single self-contained page: pending count, recent batches (tx links via configurable `explorer_tx_url`), verify form, and the proves/does-not-prove box. |

Set `api_key` to require an `X-Ledger-Key` header on the `POST` endpoints. The compose file binds the API to `127.0.0.1`.

## Design notes

* **Merkle tree** (`ledger/merkle.py`): SHA-256, domain-separated (`0x00` leaf prefix, `0x01` node prefix) and sorted-pair hashing. An odd node is **promoted, not duplicated** (duplication lets different leaf lists share a root). Hand-computed tests cover 3, 4, 5 and 7 leaves, single-leaf, and the empty-batch error. Consequence of sorted pairs: a proof shows a leaf is in the tree, not its position.
* **Leaf** = hash of a small canonical JSON record `{v, source, kind, ref, payload}`. No private content enters it: Aegis snippets are excluded and Gauntlet `variant_text` is stored only as its SHA-256.
* **Contract** (`contracts/src/AuditAnchor.sol`): `anchorBatch(root, sourceLabel, recordCount)`, `getBatch(id)`, owner-managed allowlist, custom errors. Duplicate roots are allowed (re-anchoring is harmless; each gets its own id, and the earliest id is the earliest proof). Zero root, empty batch and labels over 64 bytes are rejected. The label is emitted in the event and stored on-chain as its SHA-256, which keeps gas independent of label length.
* **Confirmations**: Ledger waits for `confirmations` blocks and re-checks the receipt's block to catch a reorg. Default 1 (a local automining chain only mines when transactions arrive, so more than 1 would wait forever there).
* **Crash window**: if the process dies after a transaction is mined but before the index is updated, those records stay `pending` and are anchored again, giving a harmless duplicate batch, never a missed record.

## Relationship to Aegis and Gauntlet

Ledger is standalone and touches the other two projects only through the interfaces they already expose; it never modifies their code and every integration degrades gracefully.

* **Aegis**: read-only `SELECT id, timestamp, direction, decision, entry_hash FROM audit_events` over a database URL (Postgres via `psycopg`, or SQLite). The row's `entry_hash` already commits to `prev_hash` and the full entry, so anchoring it covers the whole row. Collection is incremental by `id`. If Aegis is unreachable, the collector reports it and nothing is written.
* **Gauntlet**: reads `results.json`. Gauntlet's exact schema was not available when this was built, so the extractor is deliberately tolerant: it finds lists under the keys `bypasses`, `successful_bypasses`, `findings`, `misses` or `evasions` (override with `--bypass-key`), and each item needs `attack_id`, `variant_text` and `target_name` (or `target`).

**What was exercised in this build: synthetic fixtures only.** The fixtures follow the interface contract above (Aegis rows use the documented schema and the documented `entry_hash` formula, so they form genuine hash chains; the Gauntlet report has the assumed shape). Ledger has **not** been run against a real Aegis database or a real Gauntlet `results.json`. If your Gauntlet output differs, the fix is a one-line `--bypass-key` or an edit to `BYPASS_KEYS` in `ledger/sources.py`.

## What has and has not been verified

All four GitHub Actions jobs pass on the current `main`:

| area | evidence |
|---|---|
| Python lint (`ruff`, errors only) | CI `lint` job |
| Solidity contract | CI `contract-test`: `forge build`, `forge test` (access control, events, duplicate roots, input validation, fuzz tests, gas ceiling and gas-constancy tests), `forge coverage`, and a simulation of the deploy script |
| Python unit, API and **real-chain integration** tests, 80% coverage gate | CI `test` job, run against a real Anvil node (not mocked). The job fails if the integration tests are skipped rather than run. |
| Full Docker stack, tamper-detection demo, HTTP API smoke test, measured evaluation | CI `demo` job: `docker compose up --build`, `scripts/demo.sh`, `make eval` |

**Still not verified:**

* **Real Aegis and real Gauntlet data.** Everything ran against synthetic fixtures that follow the interface contract above (see the previous section). The Gauntlet `results.json` shape is an assumption.
* **Aegis over Postgres.** The collector's SQLite path is tested; the `psycopg`/Postgres path is installed in CI but not exercised against a Postgres server.
* **Any non-local chain.** Only the local Anvil chain was used. Public testnets are supported by configuration but untried, and Ledger refuses Anvil's public test keys there.
* **Platforms and versions beyond CI.** For example Apple-silicon Docker builds, and future `web3`, Foundry or image releases.

Earlier in development the Python core was also run in a sandbox without a chain (against an in-memory chain double), and spot mutation checks confirmed the tamper-detection tests fail when the logic is deliberately broken.

## Limitations

* **Allowlist trust boundary.** Only allowlisted keys can anchor, so a stranger cannot pollute the ledger with fake batches. A batch proves that *this key* anchored *this hash at this time*, not that the key belongs to the real Aegis/Gauntlet instance. A production deployment should pair this with a signed attestation from Aegis's own key (see Roadmap).
* **Garbage in, garbage out.** Data forged *before* collection is anchored faithfully. Only later changes are detected.
* **Dev chain.** Anvil is one node and its state is ephemeral here (`make reset` wipes chain and index together; `ledger deploy` archives an index orphaned by a chain reset rather than letting it look like tampering).
* **Merkle proofs show membership, not order.** Sorted-pair hashing means a swap of two sibling leaves does not change the root.
* **Gauntlet schema is assumed** (above). **Source re-checks need the source**: if Aegis or the cached copy is gone, verification reports the source check as skipped, and the verdict says so.
* No HTTP user accounts; see `SECURITY.md`.

## Responsible use

For protecting the integrity of your own audit logs and security reports. Read [`SECURITY.md`](SECURITY.md) for the trust model and reporting. Gauntlet findings can describe real weaknesses; treat the index and cached source copies as sensitive. Use only test networks and throwaway keys.

## Roadmap

* Signed attestations from Aegis's own key, verified before anchoring, so the anchor binds to the real producer.
* An optional free public-testnet (or L2) deployment guide for chain history you do not control. The config already supports it (`allow_non_local_chain`, your own throwaway keys, `explorer_tx_url`); Ledger refuses Anvil's public test keys on any non-local chain.
* Persisted Anvil state / Hardhat alternative; multi-source batches; anchor-cost dashboards.

## Repository layout

```
contracts/   AuditAnchor.sol (src/), Foundry tests (test/), Deploy.s.sol (script/), foundry.toml
ledger/      api, cli, merkle, collector, sources, anchorer, verifier, chain, config, models,
             store, service, demo, evaluation, dashboard, fixtures/ (synthetic generators)
tests/       unit, API, and real-chain integration tests
scripts/     demo.sh
results/     committed measured evaluation output
```

MIT licensed, copyright Srishti.
