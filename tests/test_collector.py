import json
import sqlite3

import pytest

from ledger.collector import collect_aegis, collect_gauntlet, collect_synthetic
from ledger.fixtures.synthetic import make_aegis_rows, make_gauntlet_report, verify_aegis_chain, wilson
from ledger.hashing import canonical_json, leaf_of_canonical, normalize_ts
from ledger.sources import (
    AegisSnapshotSource, GauntletFileSource, SourceUnavailable, aegis_canonical,
    build_source, extract_findings, redact_url, source_from_path,
)
from datetime import datetime, timezone

COLS = "id INTEGER, timestamp TEXT, api_key_id TEXT, request_id TEXT, direction TEXT, decision TEXT, " \
       "risk_score REAL, matched_rules TEXT, redactions INTEGER, content_hash TEXT, snippet TEXT, " \
       "prev_hash TEXT, entry_hash TEXT"


def make_aegis_sqlite(path, rows):
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE audit_events ({COLS})")
    for r in rows:
        conn.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (r["id"], r["timestamp"], r["api_key_id"], r["request_id"], r["direction"],
                      r["decision"], r["risk_score"], json.dumps(r["matched_rules"]), r["redactions"],
                      r["content_hash"], r["snippet"], r["prev_hash"], r["entry_hash"]))
    conn.commit()
    conn.close()


# ---- fixtures ------------------------------------------------------------------
def test_synthetic_aegis_rows_form_a_valid_chain_and_are_deterministic():
    rows = make_aegis_rows(30, seed=3)
    assert verify_aegis_chain(rows) is None
    assert rows == make_aegis_rows(30, seed=3)
    assert rows != make_aegis_rows(30, seed=4)
    rows[7]["decision"] = "block" if rows[7]["decision"] != "block" else "allow"
    assert verify_aegis_chain(rows) == rows[7]["id"]


def test_fixture_input_validation_and_wilson():
    with pytest.raises(ValueError):
        make_aegis_rows(-1)
    with pytest.raises(ValueError):
        make_gauntlet_report(-1)
    lo, hi = wilson(5, 20)
    assert 0 < lo < 0.25 < hi < 1
    assert wilson(0, 0) == (0.0, 0.0)


# ---- hashing helpers ---------------------------------------------------------------
def test_normalize_ts_is_stable_across_representations():
    dt = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert normalize_ts(dt) == normalize_ts(dt.isoformat()) == normalize_ts("2026-03-01T12:00:00Z")
    assert normalize_ts(datetime(2026, 3, 1, 12, 0, 0)) == normalize_ts(dt)  # naive treated as UTC
    assert normalize_ts("not a date") == "not a date"
    assert normalize_ts(5) == "5"


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1}) == '{"a":2,"b":1}'


# ---- Aegis ---------------------------------------------------------------------------
def test_aegis_canonical_never_contains_private_content():
    row = make_aegis_rows(1)[0]
    canon = aegis_canonical("aegis", row)
    text = canonical_json(canon)
    assert row["snippet"] not in text and "snippet" not in text
    assert set(canon["payload"]) == {"id", "timestamp", "direction", "decision", "entry_hash"}


def test_aegis_canonical_requires_columns():
    with pytest.raises(ValueError, match="missing"):
        aegis_canonical("aegis", {"id": 1})


def test_collect_aegis_from_sqlite_is_incremental_and_idempotent(tmp_path, index):
    rows = make_aegis_rows(12)
    db = tmp_path / "aegis.db"
    make_aegis_sqlite(db, rows[:8])
    url = f"sqlite:///{db}"
    first = collect_aegis(index, url)
    assert (first["read"], first["inserted"]) == (8, 8)
    again = collect_aegis(index, url)
    assert again["read"] == 0
    conn = sqlite3.connect(db)
    for r in rows[8:]:
        conn.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (r["id"], r["timestamp"], r["api_key_id"], r["request_id"], r["direction"],
                      r["decision"], r["risk_score"], "[]", r["redactions"], r["content_hash"],
                      r["snippet"], r["prev_hash"], r["entry_hash"]))
    conn.commit()
    conn.close()
    third = collect_aegis(index, url)
    assert (third["read"], third["inserted"], third["since_id"]) == (4, 4, 8)
    assert index.count_by_status()["pending"] == 12
    stored = [index.get_record(i) for i in range(1, 13)]
    assert all("snippet" not in r.canonical for r in stored)
    assert stored[0].locator == f"aegis-db:{url}"


def test_collect_aegis_limit(tmp_path, index):
    db = tmp_path / "a.db"
    make_aegis_sqlite(db, make_aegis_rows(10))
    assert collect_aegis(index, f"sqlite:///{db}", limit=4)["inserted"] == 4


def test_collect_aegis_degrades_gracefully_when_unreachable(tmp_path, index):
    with pytest.raises(SourceUnavailable):
        collect_aegis(index, f"sqlite:///{tmp_path}/does-not-exist.db")
    with pytest.raises(SourceUnavailable):
        collect_aegis(index, "postgresql://u:p@127.0.0.1:1/nope")
    assert index.count_by_status()["pending"] == 0


def test_collect_aegis_wrong_schema_is_reported(tmp_path, index):
    db = tmp_path / "bad.db"
    sqlite3.connect(db).execute("CREATE TABLE other (x)").connection.commit()
    with pytest.raises(SourceUnavailable, match="query failed"):
        collect_aegis(index, f"sqlite:///{db}")


def test_redact_url_strips_credentials():
    assert redact_url("postgresql://user:secret@db:5432/aegis") == "postgresql://db:5432/aegis"
    assert redact_url("postgresql://db/aegis") == "postgresql://db/aegis"
    assert "secret" not in redact_url("postgresql://user:secret@db/x")


def test_aegis_db_source_roundtrip(tmp_path, index):
    rows = make_aegis_rows(5)
    db = tmp_path / "a.db"
    make_aegis_sqlite(db, rows)
    collect_aegis(index, f"sqlite:///{db}")
    rec = index.get_record(3)
    src = build_source(rec.locator)
    assert leaf_of_canonical(src.lookup(rec)).hex() == rec.leaf_hash
    with pytest.raises(SourceUnavailable):
        build_source("bogus:thing")


# ---- Gauntlet -------------------------------------------------------------------------
def write_report(tmp_path, n=6, name="results.json"):
    p = tmp_path / name
    p.write_text(json.dumps(make_gauntlet_report(n)))
    return p


def test_collect_gauntlet_hashes_file_and_each_finding(tmp_path, index):
    p = write_report(tmp_path, 6)
    res = collect_gauntlet(index, str(p), str(tmp_path / "src"))
    assert res["findings"] == 6 and res["inserted"] == 7  # 6 findings + 1 report record
    kinds = [index.get_record(i).kind for i in range(1, 8)]
    assert kinds.count("report") == 1 and kinds.count("finding") == 6


def test_gauntlet_variant_text_is_hashed_not_stored(tmp_path, index):
    report = make_gauntlet_report(3)
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report))
    collect_gauntlet(index, str(p), str(tmp_path / "s"))
    for b in report["bypasses"]:
        for i in range(1, 5):
            assert b["variant_text"] not in index.get_record(i).canonical


def test_gauntlet_recollect_is_idempotent_and_caches_a_copy(tmp_path, index):
    p = write_report(tmp_path)
    r1 = collect_gauntlet(index, str(p), str(tmp_path / "s"))
    r2 = collect_gauntlet(index, str(p), str(tmp_path / "s"))
    assert r2["inserted"] == 0 and r2["skipped"] == r1["inserted"]
    assert (tmp_path / "s").exists() and r1["cached_copy"].endswith(".json")


def test_gauntlet_single_finding_changes_only_its_own_leaf(tmp_path, index):
    report = make_gauntlet_report(4)
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report))
    collect_gauntlet(index, str(p), str(tmp_path / "s"))
    report["bypasses"][1]["variant_text"] += " (edited)"
    p2 = tmp_path / "r2.json"
    p2.write_text(json.dumps(report))
    src = GauntletFileSource(str(p2))
    results = []
    for i in range(1, 6):
        rec = index.get_record(i)
        canon = src.lookup(rec)
        results.append(canon is not None and leaf_of_canonical(canon).hex() == rec.leaf_hash)
    # report record: ref is the old file's hash, so it is not found; exactly one finding differs
    assert results.count(False) == 2 and results.count(True) == 3


def test_extract_findings_tolerates_nesting_dedup_and_alt_keys():
    doc = {"runs": [{"findings": [
        {"attack_id": "a1", "target": "t", "variant_text": "v1"},
        {"attack_id": "a1", "target": "t", "variant_text": "v1"},
        {"attack_id": "a2", "target_name": "t", "variant_text": "v2"},
        {"attack_id": "a3", "variant_text": "no target"},
        "junk"]}], "other": {"bypasses": [{"attack_id": "a4", "target_name": "t", "variant_text": "v4"}]}}
    got = extract_findings(doc)
    assert [f["attack_id"] for f in got] == ["a1", "a2", "a4"]
    assert extract_findings({"x": 1}) == []
    assert extract_findings(doc, bypass_keys=("nothing",)) == []


def test_collect_gauntlet_errors(tmp_path, index):
    with pytest.raises(SourceUnavailable):
        collect_gauntlet(index, str(tmp_path / "missing.json"), str(tmp_path))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        collect_gauntlet(index, str(bad), str(tmp_path))


# ---- synthetic ----------------------------------------------------------------------------
def test_collect_synthetic_aegis_continues_ids_and_writes_snapshot(tmp_path, index):
    a = collect_synthetic(index, 10, str(tmp_path))
    b = collect_synthetic(index, 5, str(tmp_path))
    assert (a["inserted"], b["inserted"]) == (10, 5)
    refs = sorted(int(index.get_record(i).ref) for i in range(1, 16))
    assert refs == list(range(1, 16))
    snap = json.loads(open(a["snapshot"]).read())
    assert snap["source"] == "synthetic" and len(snap["rows"]) == 10
    assert index.get_record(1).source == "synthetic"


def test_collect_synthetic_gauntlet_and_validation(tmp_path, index):
    r = collect_synthetic(index, 4, str(tmp_path), kind="gauntlet")
    assert r["findings"] == 4 and r["inserted"] == 5
    with pytest.raises(ValueError):
        collect_synthetic(index, 0, str(tmp_path))
    with pytest.raises(ValueError):
        collect_synthetic(index, 3, str(tmp_path), kind="nope")


def test_source_from_path_autodetects_and_snapshot_lookup(tmp_path, index):
    r = collect_synthetic(index, 3, str(tmp_path))
    src = source_from_path(r["snapshot"])
    assert isinstance(src, AegisSnapshotSource)
    rec = index.get_record(2)
    assert leaf_of_canonical(src.lookup(rec)).hex() == rec.leaf_hash
    g = write_report(tmp_path, 2)
    assert isinstance(source_from_path(str(g)), GauntletFileSource)
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(make_aegis_rows(2)))  # a bare list is an export too
    assert isinstance(source_from_path(str(bare)), AegisSnapshotSource)
    with pytest.raises(SourceUnavailable):
        source_from_path(str(tmp_path / "nope.json"))
    with pytest.raises(SourceUnavailable):
        AegisSnapshotSource(str(tmp_path / "nope.json"))
