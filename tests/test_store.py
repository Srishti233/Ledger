import pytest

from ledger.models import NewBatch, NewRecord
from ledger.store import Index


def rec(ref, source="aegis", kind="audit_entry"):
    return NewRecord(source, kind, str(ref), "{}", "ab" * 32, "loc")


def batch(**kw):
    base = dict(chain_batch_id=1, source_label="aegis", merkle_root="cd" * 32, record_count=2,
                tx_hash="0x1", block_number=5, block_timestamp=1700000000, gas_used=100000,
                contract_address="0x" + "a" * 40, chain_id=31337, anchor_seconds=0.5)
    base.update(kw)
    return NewBatch(**base)


def test_duplicates_are_ignored(index):
    assert index.add_records([rec(1), rec(2), rec(1)]) == (2, 1)
    assert index.add_records([rec(1)]) == (0, 1)
    assert index.count_by_status() == {"pending": 2, "anchored": 0}


def test_get_missing_returns_none(index):
    assert index.get_record(99) is None and index.get_batch(99) is None


def test_record_anchor_is_atomic_and_updates_rows(index):
    index.add_records([rec(1), rec(2)])
    bid = index.record_anchor(batch(), [1, 2], ["[]", "[]"])
    assert index.count_by_status() == {"pending": 0, "anchored": 2}
    r = index.get_record(2)
    assert (r.status, r.batch_id, r.position, r.proof) == ("anchored", bid, 1, "[]")
    assert [x.id for x in index.batch_records(bid)] == [1, 2]
    assert index.get_batch(bid).tx_hash == "0x1"


def test_record_anchor_length_mismatch_and_rollback(index):
    index.add_records([rec(1)])
    with pytest.raises(ValueError):
        index.record_anchor(batch(), [1], [])
    assert index.list_batches() == []
    assert index.count_by_status()["pending"] == 1


def test_pending_filters_and_limit(index):
    index.add_records([rec(1), rec(2, source="gauntlet", kind="finding"), rec(3)])
    assert len(index.pending()) == 3
    assert [r.ref for r in index.pending(source="aegis")] == ["1", "3"]
    assert len(index.pending(limit=1)) == 1


def test_max_numeric_ref(index):
    assert index.max_numeric_ref("aegis", "audit_entry") == 0
    index.add_records([rec(5), rec(12), rec(7)])
    assert index.max_numeric_ref("aegis", "audit_entry") == 12


def test_totals_and_listing(index):
    assert index.totals()["batches"] == 0 and index.totals()["last_anchor_seconds"] is None
    index.add_records([rec(1), rec(2), rec(3)])
    index.record_anchor(batch(gas_used=10, anchor_seconds=1.0), [1], ["[]"])
    index.record_anchor(batch(chain_batch_id=2, gas_used=20, anchor_seconds=2.0), [2], ["[]"])
    t = index.totals()
    assert (t["batches"], t["gas_total"], t["records_total"]) == (2, 30, 3)
    assert t["last_anchor_seconds"] == 2.0 and t["anchor_seconds_sum"] == 3.0
    assert [b.chain_batch_id for b in index.list_batches(1)] == [2]


def test_persists_across_connections(tmp_path):
    path = tmp_path / "x" / "l.db"
    a = Index(path)
    a.add_records([rec(1)])
    a.close()
    assert Index(path).count_by_status()["pending"] == 1


def test_archive_stale_index_moves_but_never_deletes(tmp_path):
    from ledger.store import archive_stale_index

    path = tmp_path / "l.db"
    assert archive_stale_index(path) is None  # nothing there
    idx = Index(path)
    idx.add_records([rec(1)])
    assert archive_stale_index(path) is None  # no batches yet: nothing orphaned
    idx.record_anchor(batch(), [1], ["[]"])
    idx.close()
    moved = archive_stale_index(path)
    assert moved and not path.exists() and ".stale-" in moved
    assert Index(moved).get_batch(1) is not None  # content preserved
    assert archive_stale_index(":memory:") is None
