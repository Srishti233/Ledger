import html
import json
from dataclasses import replace

import pytest

from ledger.dashboard import render_dashboard
from ledger.service import LedgerService
from ledger.verifier import WHAT_NOT_PROVES, WHAT_PROVES


@pytest.fixture
def svc(cfg, index, chain):
    return LedgerService(cfg, index, chain)


def test_collect_anchor_and_read_back(svc):
    svc.collect_synthetic(6)
    (res,) = svc.anchor_now()
    rec = svc.record(2)
    assert rec["status"] == "anchored" and rec["batch"]["merkle_root"] == res.merkle_root
    assert rec["record"]["payload"]["entry_hash"] and "snippet" not in json.dumps(rec)
    proof = svc.proof(2)
    assert proof["recomputed_root"] == proof["merkle_root"] == res.merkle_root
    assert svc.batches()[0]["record_count"] == 6 and svc.batch_dict(1)["chain_id"] == 31337


def test_missing_and_pending_lookups(svc):
    with pytest.raises(LookupError):
        svc.record(1)
    with pytest.raises(LookupError):
        svc.proof(1)
    with pytest.raises(LookupError):
        svc.batch_dict(1)
    svc.collect_synthetic(2)
    with pytest.raises(LookupError, match="not anchored"):
        svc.proof(1)


def test_status_and_metrics(svc, chain):
    svc.collect_synthetic(5)
    assert svc.status()["pending"] == 5
    svc.anchor_now()
    st = svc.status()
    assert st["anchored"] == 5 and st["chain"]["connected"] and st["chain"]["local"]
    text = svc.metrics_text()
    assert "ledger_records_anchored_total 5" in text and "ledger_gas_spent_total 98765" in text
    assert text.count("# TYPE") == 8
    chain.connected = False
    assert svc.status()["chain"]["connected"] is False


def test_anchor_if_due_respects_thresholds(cfg, index, chain):
    s = LedgerService(replace(cfg, batch_size=10, max_wait_seconds=10_000), index, chain)
    s.collect_synthetic(3)
    assert s.anchor_if_due() == []
    s.collect_synthetic(7)
    assert len(s.anchor_if_due()) == 1


def test_explorer_url_only_for_http_patterns(cfg, index, chain):
    ok = LedgerService(replace(cfg, explorer_tx_url="https://x.example/tx/{tx_hash}"), index, chain)
    assert ok.explorer_url("0xabc") == "https://x.example/tx/0xabc"
    bad = LedgerService(replace(cfg, explorer_tx_url="javascript:alert(1)//{tx_hash}"), index, chain)
    assert bad.explorer_url("0xabc") == "" and LedgerService(cfg, index, chain).explorer_url("0x1") == ""


def test_collect_aegis_requires_a_url(svc):
    with pytest.raises(ValueError, match="no Aegis database URL"):
        svc.collect_aegis()


def test_service_verify_wrappers(svc):
    svc.collect_synthetic(4)
    svc.anchor_now()
    assert svc.verify_record(1).status == "verified"
    assert svc.verify_batch(1, use_source=True).status == "verified"


def test_dashboard_renders_the_exact_proof_text_with_no_template_leftovers():
    page = render_dashboard()
    assert "__PROVES__" not in page and "__NOT_PROVES__" not in page
    assert html.escape(WHAT_PROVES) in page and html.escape(WHAT_NOT_PROVES) in page
    assert "no later than block N" in page
    assert "innerHTML" not in page  # untrusted values are only ever inserted as text
