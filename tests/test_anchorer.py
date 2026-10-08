import json
from datetime import datetime, timedelta, timezone

import pytest

from ledger.anchorer import AnchorError, anchor_pending, label_for
from ledger.collector import collect_synthetic
from ledger.config import Config
from ledger.merkle import MerkleTree, proof_from_json, verify_inclusion


def test_nothing_pending_does_nothing(index, chain, cfg):
    assert anchor_pending(index, chain, cfg) == [] and chain.anchor_calls == 0


def test_anchors_everything_in_one_batch(index, chain, cfg):
    collect_synthetic(index, 25, cfg.source_dir)
    (res,) = anchor_pending(index, chain, cfg)
    assert res.record_count == 25 and res.source_label == "synthetic-aegis"
    assert index.count_by_status() == {"pending": 0, "anchored": 25}
    on = chain.get_batch(res.chain_batch_id)
    assert on.merkle_root == res.merkle_root and on.record_count == 25


def test_stored_proofs_verify_against_the_onchain_root(index, chain, cfg):
    collect_synthetic(index, 13, cfg.source_dir)
    (res,) = anchor_pending(index, chain, cfg)
    root = bytes.fromhex(chain.get_batch(res.chain_batch_id).merkle_root)
    for r in index.batch_records(res.local_batch_id):
        proof = proof_from_json(json.loads(r.proof))
        assert verify_inclusion(bytes.fromhex(r.leaf_hash), proof, root)
    leaves = [bytes.fromhex(r.leaf_hash) for r in index.batch_records(res.local_batch_id)]
    assert MerkleTree(leaves).root == root


def test_batch_size_chunks_and_positions(index, chain, cfg):
    small = Config(data_dir=cfg.data_dir, batch_size=10)
    collect_synthetic(index, 25, cfg.source_dir)
    results = anchor_pending(index, chain, small)
    assert [r.record_count for r in results] == [10, 10, 5]
    assert [r.local_batch_id for r in results] == [1, 2, 3]
    assert [r.position for r in index.batch_records(1)] == list(range(10))


def test_one_batch_per_source_label(index, chain, cfg):
    collect_synthetic(index, 4, cfg.source_dir, kind="aegis")
    collect_synthetic(index, 3, cfg.source_dir, kind="gauntlet")
    results = anchor_pending(index, chain, cfg)
    assert sorted((r.source_label, r.record_count) for r in results) == [
        ("synthetic-aegis", 4), ("synthetic-gauntlet", 4)]
    assert label_for(index.get_record(1)) == "synthetic-aegis"


def test_only_if_due_waits_for_size_or_age(index, chain, tmp_path):
    cfg = Config(batch_size=5, max_wait_seconds=60)
    collect_synthetic(index, 3, str(tmp_path))
    now = datetime.now(timezone.utc)
    assert anchor_pending(index, chain, cfg, only_if_due=True, now=now) == []
    later = now + timedelta(seconds=61)
    assert len(anchor_pending(index, chain, cfg, only_if_due=True, now=later)) == 1


def test_only_if_due_triggers_on_full_batch(index, chain, tmp_path):
    cfg = Config(batch_size=5, max_wait_seconds=10_000)
    collect_synthetic(index, 5, str(tmp_path))
    assert len(anchor_pending(index, chain, cfg, only_if_due=True)) == 1


def test_failure_leaves_records_pending_and_retry_succeeds(index, chain, cfg):
    collect_synthetic(index, 6, cfg.source_dir)
    chain.fail_next_anchor = True
    with pytest.raises(AnchorError, match="simulated"):
        anchor_pending(index, chain, cfg)
    assert index.count_by_status() == {"pending": 6, "anchored": 0}
    assert len(anchor_pending(index, chain, cfg)) == 1
    assert index.count_by_status()["anchored"] == 6


def test_on_result_callback_and_result_dict(index, chain, cfg):
    collect_synthetic(index, 3, cfg.source_dir)
    seen = []
    anchor_pending(index, chain, cfg, on_result=seen.append)
    assert len(seen) == 1 and seen[0].to_dict()["record_count"] == 3


def test_records_collected_later_go_in_a_new_batch(index, chain, cfg):
    collect_synthetic(index, 3, cfg.source_dir)
    anchor_pending(index, chain, cfg)
    collect_synthetic(index, 2, cfg.source_dir)
    (res,) = anchor_pending(index, chain, cfg)
    assert res.record_count == 2 and res.chain_batch_id == 2
