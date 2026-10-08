import json
import sqlite3

from ledger.demo import restore_index_record, run_demo, tamper_index_record, tamper_snapshot_copy
from tests.fakes import FakeChain


def test_demo_passes_and_prints_each_stage(cfg):
    lines = []
    res = run_demo(cfg, FakeChain(), count=15, out=lines.append)
    text = "\n".join(lines)
    assert res["ok"] and all(c["ok"] for c in res["checks"])
    for marker in ("[1/6]", "[2/6]", "[3/6]", "[4/6]", "[5/6]", "[6/6]", "tx hash", "gas used",
                   "LEDGER_INDEX_MODIFIED", "SOURCE_DATA_MODIFIED", "DEMO PASSED"):
        assert marker in text, marker


def test_demo_fails_loudly_if_the_chain_lies(cfg):
    class LyingChain(FakeChain):
        """A chain whose stored root no longer matches what was anchored."""
        def get_batch(self, batch_id):
            b = super().get_batch(batch_id)
            return None if b is None else type(b)(**{**b.__dict__, "merkle_root": "00" * 32})

    res = run_demo(cfg, LyingChain(), count=6, out=lambda s: None)
    assert not res["ok"]


def test_demo_removes_its_scratch_directory_on_success(cfg):
    import os
    run_demo(cfg, FakeChain(), count=5, out=lambda s: None)
    demo_root = os.path.join(cfg.data_dir, "demo")
    assert os.listdir(demo_root) == []


def test_tamper_helpers_are_reversible(tmp_path):
    db = tmp_path / "t.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE records (id INTEGER, canonical TEXT, leaf_hash TEXT)")
    canon = json.dumps({"payload": {"decision": "allow"}})
    conn.execute("INSERT INTO records VALUES (1, ?, 'aa')", (canon,))
    conn.commit()
    conn.close()
    original = tamper_index_record(str(db), 1)
    now = sqlite3.connect(db).execute("SELECT canonical, leaf_hash FROM records").fetchone()
    assert now[0] != canon and now[1] != "aa" and '"block"' in now[0]
    restore_index_record(str(db), 1, original)
    assert sqlite3.connect(db).execute("SELECT canonical, leaf_hash FROM records").fetchone() == (canon, "aa")


def test_tamper_snapshot_copy_leaves_original_untouched(tmp_path):
    src = tmp_path / "s.json"
    src.write_text(json.dumps({"rows": [{"id": 1, "decision": "allow"}, {"id": 2, "decision": "block"}]}))
    dst = tmp_path / "d.json"
    tamper_snapshot_copy(str(src), str(dst), 2)
    assert json.loads(src.read_text())["rows"][1]["decision"] == "block"
    assert json.loads(dst.read_text())["rows"][1]["decision"] == "allow"
    assert json.loads(dst.read_text())["rows"][0]["decision"] == "allow"
