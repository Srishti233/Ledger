"""The tamper-detection demo. Runs against whatever ChainClient it is given (the real
local Anvil chain in Docker/CI) using its own isolated index and synthetic data."""

from __future__ import annotations

import copy
import json
import shutil
import sqlite3
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .anchorer import anchor_pending
from .chain import ChainClient
from .config import Config
from .hashing import canonical_json, leaf_of_canonical
from .collector import collect_synthetic
from .sources import source_from_path
from .store import Index
from .verifier import Verifier

FLIP = {"allow": "block", "block": "allow", "redact": "allow"}


def tamper_index_record(db_path: str, record_id: int) -> dict:
    """Simulate a compromised Ledger server: edit a record's content AND recompute its
    stored leaf so the row looks self-consistent. Returns the original column values."""
    conn = sqlite3.connect(db_path)
    try:
        canonical, leaf = conn.execute(
            "SELECT canonical, leaf_hash FROM records WHERE id=?", (record_id,)).fetchone()
        obj = json.loads(canonical)
        obj["payload"]["decision"] = FLIP.get(obj["payload"]["decision"], "allow")
        conn.execute("UPDATE records SET canonical=?, leaf_hash=? WHERE id=?",
                     (canonical_json(obj), leaf_of_canonical(obj).hex(), record_id))
        conn.commit()
        return {"canonical": canonical, "leaf_hash": leaf}
    finally:
        conn.close()


def restore_index_record(db_path: str, record_id: int, original: dict) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE records SET canonical=?, leaf_hash=? WHERE id=?",
                     (original["canonical"], original["leaf_hash"], record_id))
        conn.commit()
    finally:
        conn.close()


def tamper_snapshot_copy(src: str, dst: str, row_id: int) -> None:
    """Simulate a compromised Aegis database: edit one row in a COPY of the audit table."""
    data = json.loads(Path(src).read_text())
    data = copy.deepcopy(data)
    for row in data["rows"]:
        if row["id"] == row_id:
            row["decision"] = FLIP.get(row["decision"], "allow")
    Path(dst).write_text(json.dumps(data, indent=1))


def run_demo(cfg: Config, chain: ChainClient, count: int = 25,
             out: Callable[[str], None] = print) -> dict:
    """Run the full flow. Returns {"ok": bool, "steps": [...]}; ok is False if any expected
    outcome (verify passes, then both tamper cases are detected for the right reason) fails."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    work = Path(cfg.data_dir) / "demo" / stamp
    work.mkdir(parents=True, exist_ok=True)
    dcfg = replace(cfg, data_dir=str(work), db_path=str(work / "ledger-demo.db"),
                   batch_size=max(count, 1), confirmations=cfg.confirmations)
    index = Index(dcfg.database)
    checks: list[dict] = []

    def expect(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"expectation": name, "ok": bool(ok), "detail": detail})
        out(f"  -> {'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))

    try:
        out(f"Ledger demo: chain connected={chain.is_connected()} contract={chain.contract_address}")
        out(f"\n[1/6] Collect {count} synthetic Aegis-style audit records (source = 'synthetic').")
        col = collect_synthetic(index, count, dcfg.source_dir)
        out(f"  collected {col['inserted']} records, source snapshot: {col['snapshot']}")

        out("\n[2/6] Build a Merkle tree and anchor its root on-chain.")
        t0 = time.perf_counter()
        results = anchor_pending(index, chain, dcfg)
        r = results[0]
        out(f"  tx hash   : {r.tx_hash}\n  block     : {r.block_number}\n  gas used  : {r.gas_used}"
            f"\n  root      : {r.merkle_root}\n  records   : {r.record_count}"
            f"\n  took      : {time.perf_counter() - t0:.3f}s")
        expect("exactly one batch anchored", len(results) == 1 and r.record_count == count)

        verifier = Verifier(index, chain, dcfg)
        out("\n[3/6] Verify the batch (index vs live chain).")
        v = verifier.verify_batch(r.local_batch_id)
        out(v.render_text())
        expect("clean batch verifies", v.status == "verified")
        v_full = verifier.verify_batch(r.local_batch_id, source=source_from_path(col["snapshot"], "synthetic"))
        expect("clean batch verifies with the full source record set supplied", v_full.status == "verified")

        records = index.batch_records(r.local_batch_id)
        target = records[len(records) // 2]
        out(f"\n[4/6] TAMPER with Ledger's own SQLite index (record {target.id}, {target.ref}) "
            "-- simulating a compromised Ledger server.")
        original = tamper_index_record(dcfg.database, target.id)
        v4 = verifier.verify_batch(r.local_batch_id)
        out(v4.render_text())
        expect("index tampering is detected", v4.status == "tamper_detected")
        expect("report identifies exactly the tampered record", v4.index_culprits == [target.id],
               f"culprits={v4.index_culprits}")
        expect("diagnosed as a Ledger-index problem, source untouched",
               "LEDGER_INDEX_MODIFIED" in v4.causes and "SOURCE_DATA_MODIFIED" not in v4.causes)
        restore_index_record(dcfg.database, target.id, original)
        expect("restoring the row makes the batch verify again",
               verifier.verify_batch(r.local_batch_id).status == "verified")

        out(f"\n[5/6] TAMPER with a COPY of the Aegis audit table fixture (row id {target.ref}) "
            "-- simulating a compromised Aegis database; verify with the full record set supplied.")
        bad_copy = str(work / "tampered-aegis-copy.json")
        tamper_snapshot_copy(col["snapshot"], bad_copy, int(target.ref))
        v5 = verifier.verify_batch(r.local_batch_id, source=source_from_path(bad_copy, "synthetic"))
        out(v5.render_text())
        expect("source tampering is detected", v5.status == "tamper_detected")
        expect("report identifies exactly the tampered source row", v5.source_culprits == [target.id],
               f"culprits={v5.source_culprits}")
        expect("diagnosed as source-data modification; index and on-chain root intact",
               v5.causes == ["SOURCE_DATA_MODIFIED"] and not v5.index_culprits)

        out("\n[6/6] What each result proves")
        out("  Clean run     : the anchored root equals the root recomputed from the index, and every\n"
            "                  record is included in it. The records existed no later than the anchor block.")
        out("  Index tamper  : the on-chain root did not change, so the edit is exposed. The chain, not\n"
            "                  Ledger's database, is the authority; the failing record is named.")
        out("  Source tamper : the index and the on-chain root are intact, but the record recomputed from\n"
            "                  the modified source no longer hashes to the anchored leaf -- a different,\n"
            "                  correctly-labelled failure.")
        out("  Neither case proves the original data was TRUE, only that it is unchanged since anchoring.")
    finally:
        index.close()
        if all(c["ok"] for c in checks) and checks:
            shutil.rmtree(work, ignore_errors=True)
    ok = bool(checks) and all(c["ok"] for c in checks)
    out(f"\nDEMO {'PASSED' if ok else 'FAILED'}: {sum(c['ok'] for c in checks)}/{len(checks)} expectations met")
    return {"ok": ok, "checks": checks}
