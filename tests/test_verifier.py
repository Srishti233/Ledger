import json
import sqlite3
from dataclasses import replace

import pytest

from ledger.demo import restore_index_record, tamper_index_record, tamper_snapshot_copy
from ledger.hashing import canonical_json, leaf_of_canonical
from ledger.sources import AegisSnapshotSource, source_from_path
from ledger.verifier import (
    INCONCLUSIVE, TAMPER, VERIFIED, SourceResult, Verifier, evaluate_batch, evaluate_record,
    label_hash,
)


def names(v, status):
    return [c.name for c in v.checks if c.status == status]


def load(index, chain, anchored):
    batch = index.get_batch(anchored["batch_id"])
    records = index.batch_records(batch.id)
    return batch, records, chain.get_batch(batch.chain_batch_id)


def source_for(anchored, rec):
    snap = AegisSnapshotSource(anchored["collect"]["snapshot"], "synthetic")
    return SourceResult(True, snap.lookup(rec))


# ---- pure functions: records ---------------------------------------------------------------
def test_clean_record_verifies(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_record(records[3], batch, on, "", source_for(anchored, records[3]))
    assert v.status == VERIFIED and v.exit_code == 0 and not v.causes
    assert not names(v, "fail") and v.source_checked
    assert any("existed no later than" in p for p in v.proven)


def test_clean_record_without_source_is_verified_but_says_source_unchecked(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_record(records[0], batch, on, "", SourceResult(False, note="offline"))
    assert v.status == VERIFIED and not v.source_checked
    assert "source_matches_anchor" in names(v, "skipped")
    assert any("NOT" not in p and "not re-checked" in p for p in v.not_proven)


def test_index_tamper_consistent_leaf_is_caught(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    c = json.loads(records[2].canonical)
    c["payload"]["decision"] = "allow" if c["payload"]["decision"] != "allow" else "block"
    forged = replace(records[2], canonical=canonical_json(c), leaf_hash=leaf_of_canonical(c).hex())
    v = evaluate_record(forged, batch, on, "", SourceResult(False))
    assert v.status == TAMPER and v.exit_code == 1
    assert v.causes == ["LEDGER_INDEX_MODIFIED"] and v.index_culprits == [forged.id]
    assert "leaf_included_in_onchain_root" in names(v, "fail")


def test_index_tamper_content_only_is_caught(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    forged = replace(records[1], canonical=records[1].canonical.replace("block", "allow") + " ")
    v = evaluate_record(forged, batch, on, "", SourceResult(False))
    assert v.status == TAMPER and "index_leaf_consistent" in names(v, "fail")


def test_source_tamper_is_a_different_diagnosis(index, chain, anchored, tmp_path):
    batch, records, on = load(index, chain, anchored)
    rec = records[5]
    bad = tmp_path / "bad.json"
    tamper_snapshot_copy(anchored["collect"]["snapshot"], str(bad), int(rec.ref))
    src = SourceResult(True, AegisSnapshotSource(str(bad), "synthetic").lookup(rec))
    v = evaluate_record(rec, batch, on, "", src)
    assert v.status == TAMPER and v.causes == ["SOURCE_DATA_MODIFIED"]
    assert v.source_culprits == [rec.id] and not v.index_culprits
    assert not [n for n in names(v, "fail") if n != "source_matches_anchor"]


def test_missing_source_record(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_record(records[0], batch, on, "", SourceResult(True, None))
    assert v.causes == ["SOURCE_RECORD_MISSING"] and v.status == TAMPER


def test_stored_batch_root_tampered(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_record(records[0], replace(batch, merkle_root="ee" * 32), on, "", SourceResult(False))
    assert v.status == TAMPER and "ONCHAIN_ROOT_MISMATCH" in v.causes


def test_metadata_tamper_detected(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    for field, value in [("record_count", 999), ("block_number", 1), ("source_label", "other"),
                         ("contract_address", "0x" + "cd" * 20)]:
        v = evaluate_record(records[0], replace(batch, **{field: value}), on, "", SourceResult(False))
        assert "CHAIN_METADATA_MISMATCH" in v.causes, field


def test_batch_missing_on_chain(index, chain, anchored):
    batch, records, _ = load(index, chain, anchored)
    v = evaluate_record(records[0], batch, None, "", SourceResult(False))
    assert v.status == TAMPER and "BATCH_NOT_ON_CHAIN" in v.causes


def test_chain_unreachable_is_inconclusive_not_a_pass(index, chain, anchored):
    batch, records, _ = load(index, chain, anchored)
    v = evaluate_record(records[0], batch, None, "connection refused", SourceResult(False))
    assert v.status == INCONCLUSIVE and v.exit_code == 2
    assert any("NOT a pass" in p for p in v.not_proven)


def test_garbage_proof_and_leaf_do_not_crash(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    for bad in (replace(records[0], proof="not json"), replace(records[0], proof=None),
                replace(records[0], leaf_hash="zz"), replace(records[0], proof='[{"x":1}]')):
        assert evaluate_record(bad, batch, on, "", SourceResult(False)).status == TAMPER


# ---- pure functions: batches ------------------------------------------------------------------
def test_clean_batch_verifies(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_batch(batch, records, on, "", None)
    assert v.status == VERIFIED and "source_full_record_set" in names(v, "skipped")


def test_batch_index_tamper_localises_the_record(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    c = json.loads(records[7].canonical)
    c["payload"]["decision"] = "block" if c["payload"]["decision"] != "block" else "allow"
    records[7] = replace(records[7], canonical=canonical_json(c), leaf_hash=leaf_of_canonical(c).hex())
    v = evaluate_batch(batch, records, on, "", None)
    assert v.status == TAMPER and v.index_culprits == [records[7].id]
    assert "recomputed_root_equals_chain_root" in names(v, "fail")
    assert v.causes == ["LEDGER_INDEX_MODIFIED"]


def test_batch_source_tamper_with_full_set(index, chain, anchored, tmp_path):
    batch, records, on = load(index, chain, anchored)
    bad = tmp_path / "bad.json"
    tamper_snapshot_copy(anchored["collect"]["snapshot"], str(bad), int(records[9].ref))
    snap = AegisSnapshotSource(str(bad), "synthetic")
    sources = {r.id: SourceResult(True, snap.lookup(r)) for r in records}
    v = evaluate_batch(batch, records, on, "", sources)
    assert v.status == TAMPER and v.causes == ["SOURCE_DATA_MODIFIED"]
    assert v.source_culprits == [records[9].id] and not v.index_culprits
    assert "recomputed_root_equals_chain_root" in names(v, "pass")  # index and chain root intact


def test_both_index_and_source_tampered_blames_index(index, chain, anchored, tmp_path):
    # If the index is wrong, a mismatching source is not blamed on the source alone.
    batch, records, on = load(index, chain, anchored)
    c = json.loads(records[0].canonical)
    c["payload"]["decision"] = "allow" if c["payload"]["decision"] != "allow" else "block"
    records[0] = replace(records[0], canonical=canonical_json(c), leaf_hash=leaf_of_canonical(c).hex())
    snap = AegisSnapshotSource(anchored["collect"]["snapshot"], "synthetic")  # source is intact
    sources = {r.id: SourceResult(True, snap.lookup(r)) for r in records}
    v = evaluate_batch(batch, records, on, "", sources)
    assert v.status == TAMPER and v.index_culprits == [records[0].id] and not v.source_culprits


def test_deleted_or_extra_rows_flagged(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_batch(batch, records[:-1], on, "", None)
    assert v.status == TAMPER and "RECORD_SET_INCOMPLETE" in v.causes
    gap = records[:3] + records[4:]
    assert "RECORD_SET_INCOMPLETE" in evaluate_batch(batch, gap, on, "", None).causes
    assert evaluate_batch(batch, [], on, "", None).status == TAMPER


def test_batch_unreachable_and_missing(index, chain, anchored):
    batch, records, _ = load(index, chain, anchored)
    assert evaluate_batch(batch, records, None, "down", None).status == INCONCLUSIVE
    assert evaluate_batch(batch, records, None, "", None).causes == ["BATCH_NOT_ON_CHAIN"]


def test_verdict_rendering_and_json_state_the_limits(index, chain, anchored):
    batch, records, on = load(index, chain, anchored)
    v = evaluate_batch(batch, records, on, "", None)
    text, d = v.render_text(), v.to_dict()
    assert "VERIFIED" in text and "What was NOT proven" in text
    assert "does NOT prove" in d["limitation"] and d["status"] == VERIFIED
    assert json.dumps(d)
    bad = evaluate_batch(batch, records[:-1], on, "", None)
    assert "Diagnosis" in bad.render_text()


def test_label_hash_matches_contract_definition():
    import hashlib
    assert label_hash("aegis") == hashlib.sha256(b"aegis").hexdigest()


# ---- Verifier class with a live (fake) chain and real SQLite tampering -------------------------
def test_verifier_end_to_end_index_tamper(cfg, index, chain, anchored):
    v = Verifier(index, chain, cfg)
    assert v.verify_batch(anchored["batch_id"]).status == VERIFIED
    original = tamper_index_record(cfg.database, 10)
    rep = v.verify_batch(anchored["batch_id"])
    assert rep.status == TAMPER and rep.index_culprits == [10]
    assert v.verify_record(10).status == TAMPER and v.verify_record(11).status == VERIFIED
    restore_index_record(cfg.database, 10, original)
    assert v.verify_batch(anchored["batch_id"]).status == VERIFIED


def test_verifier_detects_a_replaced_index_root(cfg, index, chain, anchored):
    conn = sqlite3.connect(cfg.database)
    conn.execute("UPDATE batches SET merkle_root=?", ("ab" * 32,))
    conn.commit()
    v = Verifier(index, chain, cfg).verify_batch(anchored["batch_id"])
    assert v.status == TAMPER and "ONCHAIN_ROOT_MISMATCH" in v.causes


def test_verifier_detects_deleted_index_row(cfg, index, chain, anchored):
    conn = sqlite3.connect(cfg.database)
    conn.execute("DELETE FROM records WHERE id=4")
    conn.commit()
    v = Verifier(index, chain, cfg).verify_batch(anchored["batch_id"])
    assert v.status == TAMPER and "RECORD_SET_INCOMPLETE" in v.causes


def test_verifier_full_set_from_stored_locators_and_override(cfg, index, chain, anchored, tmp_path):
    v = Verifier(index, chain, cfg)
    assert v.verify_batch(anchored["batch_id"], use_source=True).status == VERIFIED
    assert v.verify_record(5).source_checked
    bad = tmp_path / "bad.json"
    tamper_snapshot_copy(anchored["collect"]["snapshot"], str(bad), 6)
    rep = v.verify_batch(anchored["batch_id"], source=source_from_path(str(bad), "synthetic"))
    assert rep.status == TAMPER and rep.causes == ["SOURCE_DATA_MODIFIED"]
    assert v.verify_record(6, source=source_from_path(str(bad), "synthetic")).status == TAMPER


def test_verifier_survives_missing_source_file(cfg, index, chain, anchored):
    import os
    os.remove(anchored["collect"]["snapshot"])
    v = Verifier(index, chain, cfg)
    rec = v.verify_record(2)
    assert rec.status == VERIFIED and not rec.source_checked
    batch = v.verify_batch(anchored["batch_id"], use_source=True)
    assert batch.status == VERIFIED and any("skipped" in p for p in batch.not_proven)


def test_verifier_chain_down_and_pending_and_unknown(cfg, index, chain, anchored):
    from ledger.collector import collect_synthetic
    v = Verifier(index, chain, cfg)
    chain.connected = False
    assert v.verify_batch(anchored["batch_id"]).status == INCONCLUSIVE
    assert v.verify_record(1).status == INCONCLUSIVE
    chain.connected = True
    collect_synthetic(index, 2, cfg.source_dir)
    pending = v.verify_record(26)
    assert pending.status == INCONCLUSIVE and any("pending" in c.detail for c in pending.checks)
    with pytest.raises(LookupError):
        v.verify_record(9999)
    with pytest.raises(LookupError):
        v.verify_batch(9999)


def test_use_source_false_skips_source(cfg, index, chain, anchored):
    assert not Verifier(index, chain, cfg).verify_record(3, use_source=False).source_checked
