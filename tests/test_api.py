import json
from dataclasses import replace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from ledger.api import create_app  # noqa: E402
from ledger.demo import tamper_index_record  # noqa: E402
from ledger.fixtures.synthetic import make_gauntlet_report  # noqa: E402
from ledger.service import LedgerService  # noqa: E402


@pytest.fixture
def client(cfg, index, chain):
    return TestClient(create_app(cfg, LedgerService(cfg, index, chain)))


def seed(client, n=8):
    assert client.post("/collect/synthetic", json={"count": n}).status_code == 200
    r = client.post("/anchor-now")
    assert r.status_code == 200
    return r.json()["anchored"][0]


def test_health_status_and_dashboard(client):
    assert client.get("/health").json()["status"] == "ok"
    st = client.get("/status").json()
    assert st["pending"] == 0 and st["chain"]["connected"] is True and st["chain"]["local"] is True
    page = client.get("/dashboard")
    assert page.status_code == 200 and "does not prove" in page.text.lower()
    assert "existed no later than block N" in page.text
    assert client.get("/", follow_redirects=False).status_code in (302, 307)


def test_collect_anchor_read_flow(client):
    batch = seed(client, 8)
    assert batch["record_count"] == 8
    rec = client.get("/records/3").json()
    assert rec["status"] == "anchored" and rec["batch"]["record_count"] == 8
    proof = client.get("/records/3/proof").json()
    assert proof["recomputed_root"] == proof["merkle_root"]
    b = client.get("/batches/1").json()
    assert b["merkle_root"] == batch["merkle_root"]
    assert len(client.get("/batches").json()) == 1
    assert client.get("/status").json()["anchored"] == 8


def test_verify_endpoints_pass_then_detect_tampering(client, cfg):
    seed(client, 8)
    assert client.get("/verify/2").json()["status"] == "verified"
    assert client.get("/verify/batch/1?full=true").json()["status"] == "verified"
    tamper_index_record(cfg.database, 5)
    bad = client.get("/verify/batch/1").json()
    assert bad["status"] == "tamper_detected" and bad["index_culprit_record_ids"] == [5]
    assert client.get("/verify/5").json()["status"] == "tamper_detected"
    assert "limitation" in bad and bad["what_was_not_proven"]


def test_not_found_and_validation_errors(client):
    assert client.get("/records/99").status_code == 404
    assert client.get("/records/99/proof").status_code == 404
    assert client.get("/verify/99").status_code == 404
    assert client.get("/verify/batch/99").status_code == 404
    assert client.get("/batches/99").status_code == 404
    assert client.get("/records/abc").status_code == 422
    assert client.post("/collect/synthetic", json={"count": 0}).status_code == 422
    assert client.post("/collect/synthetic", json={"kind": "nope"}).status_code == 422


def test_proof_before_anchoring_is_404(client):
    client.post("/collect/synthetic", json={"count": 2})
    assert client.get("/records/1/proof").status_code == 404
    assert client.get("/records/1").json()["status"] == "pending"
    assert client.get("/verify/1").json()["status"] == "inconclusive"


def test_metrics_exposition(client):
    seed(client, 5)
    text = client.get("/metrics").text
    assert "ledger_records_anchored_total 5" in text
    assert "ledger_records_pending 0" in text and "ledger_batches_anchored_total 1" in text
    assert "# TYPE ledger_gas_spent_total counter" in text and "ledger_anchor_latency_seconds_count 1" in text


def test_anchor_failure_maps_to_502(client, chain):
    client.post("/collect/synthetic", json={"count": 2})
    chain.fail_next_anchor = True
    assert client.post("/anchor-now").status_code == 502


def test_api_key_protects_mutations_only(cfg, index, chain):
    secured = replace(cfg, api_key="s3cret")
    c = TestClient(create_app(secured, LedgerService(secured, index, chain)))
    assert c.post("/collect/synthetic", json={"count": 2}).status_code == 401
    assert c.post("/anchor-now", headers={"X-Ledger-Key": "wrong"}).status_code == 401
    assert c.post("/collect/synthetic", json={"count": 2}, headers={"X-Ledger-Key": "s3cret"}).status_code == 200
    assert c.get("/status").status_code == 200 and c.get("/health").status_code == 200


def test_gauntlet_collection_is_confined_to_the_inbox(client, cfg):
    import os
    os.makedirs(cfg.inbox, exist_ok=True)
    with open(os.path.join(cfg.inbox, "results.json"), "w") as f:
        json.dump(make_gauntlet_report(3), f)
    ok = client.post("/collect/gauntlet", json={"results_path": "results.json"})
    assert ok.status_code == 200 and ok.json()["findings"] == 3
    assert client.post("/collect/gauntlet", json={"results_path": "../ledger.db"}).status_code == 400
    assert client.post("/collect/gauntlet", json={"results_path": "/etc/passwd"}).status_code == 400
    assert client.post("/collect/gauntlet", json={"results_path": "missing.json"}).status_code == 503


def test_aegis_collection_uses_server_config_only(client):
    r = client.post("/collect/aegis", json={"db_url": "postgresql://attacker/x"})
    assert r.status_code == 400 and "no Aegis database URL" in r.json()["detail"]


def test_aegis_collection_from_configured_sqlite(cfg, index, chain, tmp_path):
    from tests.test_collector import make_aegis_sqlite
    from ledger.fixtures.synthetic import make_aegis_rows
    make_aegis_sqlite(tmp_path / "a.db", make_aegis_rows(5))
    c2 = replace(cfg, aegis_db_url=f"sqlite:///{tmp_path}/a.db")
    c = TestClient(create_app(c2, LedgerService(c2, index, chain)))
    assert c.post("/collect/aegis").json()["inserted"] == 5
    c2b = replace(cfg, aegis_db_url=f"sqlite:///{tmp_path}/gone.db")
    d = TestClient(create_app(c2b, LedgerService(c2b, index, chain)))
    assert d.post("/collect/aegis").status_code == 503


def test_explorer_link_pattern(cfg, index, chain):
    c2 = replace(cfg, explorer_tx_url="https://explorer.example/tx/{tx_hash}")
    c = TestClient(create_app(c2, LedgerService(c2, index, chain)))
    seed(c, 3)
    url = c.get("/batches/1").json()["explorer_url"]
    assert url.startswith("https://explorer.example/tx/0x")
    c3 = replace(cfg, explorer_tx_url="javascript:alert(1)//{tx_hash}")
    d = TestClient(create_app(c3, LedgerService(c3, index, chain)))
    assert d.get("/batches/1").json()["explorer_url"] == ""
