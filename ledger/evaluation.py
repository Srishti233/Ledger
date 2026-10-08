"""Measured evaluation: real timings and gas, written to results/."""

from __future__ import annotations

import json
import platform
import statistics
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .anchorer import anchor_pending
from .chain import ChainClient
from .collector import collect_synthetic
from .config import Config
from .merkle import MerkleTree, leaf_hash, verify_inclusion
from .store import Index
from .verifier import Verifier

# ILLUSTRATIVE ASSUMPTIONS, not live prices and not measurements. Edit as you like.
ILLUSTRATIVE_GAS_PRICE_GWEI = {
    "Ethereum L1, assumed 20 gwei": 20.0,
    "Typical rollup L2, assumed 0.05 gwei": 0.05,
    "Low-fee public testnet (no real value)": 0.0,
}


def _median_ms(fn, reps: int) -> float:
    times = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times)


def merkle_bench(sizes: list[int]) -> list[dict]:
    """Pure-Python Merkle timings (no chain). Safe to run anywhere."""
    rows = []
    for n in sizes:
        leaves = [leaf_hash(f"record-{i}".encode()) for i in range(n)]
        build = _median_ms(lambda: MerkleTree(leaves), 5 if n >= 1000 else 20)
        tree = MerkleTree(leaves)
        mid = n // 2
        proof = tree.proof(mid)
        rows.append({
            "records": n,
            "tree_build_ms": round(build, 3),
            "proof_generate_ms": round(_median_ms(lambda: tree.proof(mid), 200), 4),
            "proof_verify_ms": round(_median_ms(lambda: verify_inclusion(leaves[mid], proof, tree.root), 500), 4),
            "proof_length": len(proof),
        })
    return rows


def environment() -> dict:
    return {"ledger_version": __version__, "python": sys.version.split()[0],
            "platform": platform.platform(), "measured_at": datetime.now(timezone.utc).isoformat()}


WARMUP_ROOT = bytes([0x5A]) * 32


def chain_eval(cfg: Config, chain: ChainClient, sizes: list[int]) -> tuple[list[dict], int]:
    """Run the demo flow for each batch size against the live chain and record gas/timing.

    A throwaway warm-up anchor (label "eval-warmup") is sent first: the very first
    anchorBatch on a fresh contract also initialises ``batchCount`` (0 -> 1), which costs
    more than later calls. Measuring after it makes every row steady-state. Returns
    (rows, warmup_gas).
    """
    warmup_gas = chain.anchor_batch(WARMUP_ROOT, "eval-warmup", 1, cfg.tx_timeout_seconds).gas_used
    rows = []
    for n in sizes:
        with tempfile.TemporaryDirectory() as tmp:
            ecfg = replace(cfg, data_dir=tmp, db_path=str(Path(tmp) / "eval.db"), batch_size=n)
            index = Index(ecfg.database)
            try:
                collect_synthetic(index, n, ecfg.source_dir)
                t = time.perf_counter()
                results = anchor_pending(index, chain, ecfg)
                anchor_s = time.perf_counter() - t
                res = results[0]
                verifier = Verifier(index, chain, ecfg)
                rec_id = index.batch_records(res.local_batch_id)[n // 2].id
                rec = index.get_record(rec_id)
                from .merkle import proof_from_json
                proof = proof_from_json(json.loads(rec.proof))
                leaf, root = bytes.fromhex(rec.leaf_hash), bytes.fromhex(res.merkle_root)
                rows.append({
                    "records": n,
                    "batches_sent": len(results),
                    "gas_used": res.gas_used,
                    "anchor_seconds": round(anchor_s, 4),
                    "inclusion_proof_verify_ms": round(_median_ms(lambda: verify_inclusion(leaf, proof, root), 500), 4),
                    "record_verify_with_chain_ms": round(_median_ms(lambda: verifier.verify_record(rec_id, use_source=False), 5), 3),
                    "batch_verify_with_chain_ms": round(_median_ms(lambda: verifier.verify_batch(res.local_batch_id), 3), 3),
                    "verdict": verifier.verify_batch(res.local_batch_id).status,
                })
            finally:
                index.close()
    return rows, warmup_gas


def illustrative_costs(gas_used: int) -> list[dict]:
    return [{"scenario": name, "cost_eth_per_batch": gas_used * gwei * 1e-9,
             "note": "illustrative assumption, not a live price feed"}
            for name, gwei in ILLUSTRATIVE_GAS_PRICE_GWEI.items()]


def render_markdown(report: dict) -> str:
    env = report["environment"]
    lines = [f"# Ledger evaluation ({env['measured_at']})", "",
             f"Ledger {env['ledger_version']}, Python {env['python']}, {env['platform']}", ""]
    if report.get("chain"):
        c = report["chain"]
        lines += ["## Against the live local chain", "",
                  "| records | gas used | anchor (s) | inclusion-proof verify (ms) | record verify incl. chain (ms) | batch verify incl. chain (ms) | verdict |",
                  "|---:|---:|---:|---:|---:|---:|---|"]
        for r in c:
            lines.append(f"| {r['records']} | {r['gas_used']} | {r['anchor_seconds']} | {r['inclusion_proof_verify_ms']} "
                         f"| {r['record_verify_with_chain_ms']} | {r['batch_verify_with_chain_ms']} | {r['verdict']} |")
        gas = [r["gas_used"] for r in c]
        lines += ["", f"Gas range across batch sizes: {min(gas)} to {max(gas)} "
                  f"(spread {max(gas) - min(gas)}).",
                  f"A throwaway warm-up anchor ran first (gas {report.get('warmup_gas')}) and is excluded "
                  "from the table. On a brand-new contract the very first anchor also initialises the "
                  "batch counter and can cost more than later ones; on a contract that already holds "
                  "batches, as here if other anchors ran first, the warm-up is just another steady-state call.", "",
                  "### Illustrative cost per batch (assumptions, not a live price feed)", "",
                  "| scenario | cost per batch (ETH) |", "|---|---:|"]
        for x in illustrative_costs(max(gas)):
            lines.append(f"| {x['scenario']} | {x['cost_eth_per_batch']:.9f} |")
        lines.append("")
    if report.get("merkle"):
        lines += ["## Pure-Python Merkle timings (no chain)", "",
                  "| records | tree build (ms) | proof generate (ms) | proof verify (ms) | proof length |",
                  "|---:|---:|---:|---:|---:|"]
        for r in report["merkle"]:
            lines.append(f"| {r['records']} | {r['tree_build_ms']} | {r['proof_generate_ms']} | {r['proof_verify_ms']} | {r['proof_length']} |")
        lines.append("")
    return "\n".join(lines)


def run_eval(cfg: Config, chain: ChainClient | None, sizes: list[int], out_dir: str) -> dict:
    rows, warmup = chain_eval(cfg, chain, sizes) if chain is not None else (None, None)
    report = {"environment": environment(), "sizes": sizes, "merkle": merkle_bench(sizes),
              "chain": rows, "warmup_gas": warmup}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = "eval" if chain is not None else "merkle_bench"
    (out / f"{name}.json").write_text(json.dumps(report, indent=2))
    (out / f"{name}.md").write_text(render_markdown(report))
    return report
