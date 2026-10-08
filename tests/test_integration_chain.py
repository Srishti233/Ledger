"""Integration tests against a REAL Anvil chain (no mocks).

Run locally:   anvil &   (cd contracts && forge build)   pytest -m integration
CI starts Anvil itself. If no chain/artifact/web3 is available these tests are skipped,
never silently passed."""

import os
from dataclasses import replace

import pytest

from ledger.anchorer import anchor_pending
from ledger.chain import ChainError, Web3ChainClient, ensure_deployment, load_artifact, make_chain
from ledger.collector import collect_synthetic
from ledger.config import Config
from ledger.demo import run_demo, tamper_index_record, tamper_snapshot_copy
from ledger.sources import source_from_path
from ledger.store import Index
from ledger.verifier import Verifier

pytestmark = pytest.mark.integration

RPC = os.environ.get("LEDGER_TEST_RPC_URL", "http://127.0.0.1:8545")
ANVIL_ACCOUNT_2_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"


@pytest.fixture
def live(tmp_path):
    pytest.importorskip("web3")
    cfg = Config(rpc_url=RPC, data_dir=str(tmp_path), batch_size=1000).validate()
    try:
        load_artifact(cfg.artifact_path)
    except ChainError as exc:
        pytest.skip(f"contract not built: {exc}")
    try:
        dep, fresh = ensure_deployment(cfg)
    except ChainError as exc:
        pytest.skip(f"no chain at {RPC}: {exc}")
    chain = make_chain(cfg)
    index = Index(cfg.database)
    yield cfg, chain, index
    index.close()


def test_deploy_is_idempotent(live):
    cfg, chain, _ = live
    dep, fresh = ensure_deployment(cfg)
    assert fresh is False and dep["contract_address"] == chain.contract_address


def test_anchor_verify_tamper_reverify_against_real_chain(live):
    cfg, chain, index = live
    col = collect_synthetic(index, 40, cfg.source_dir)
    (res,) = anchor_pending(index, chain, cfg)
    assert res.gas_used > 21_000 and res.tx_hash.startswith("0x") and len(res.tx_hash) == 66
    on = chain.get_batch(res.chain_batch_id)
    assert on.merkle_root == res.merkle_root and on.record_count == 40 and on.block_number == res.block_number

    verifier = Verifier(index, chain, cfg)
    assert verifier.verify_batch(res.local_batch_id).status == "verified"
    assert verifier.verify_batch(res.local_batch_id, use_source=True).status == "verified"
    assert verifier.verify_record(7).status == "verified"

    original = tamper_index_record(cfg.database, 20)
    bad = verifier.verify_batch(res.local_batch_id)
    assert bad.status == "tamper_detected" and bad.index_culprits == [20]

    import sqlite3
    conn = sqlite3.connect(cfg.database)
    conn.execute("UPDATE records SET canonical=?, leaf_hash=? WHERE id=20", (original["canonical"], original["leaf_hash"]))
    conn.commit()
    bad_copy = os.path.join(cfg.data_dir, "tampered.json")
    tamper_snapshot_copy(col["snapshot"], bad_copy, 11)
    src_bad = verifier.verify_batch(res.local_batch_id, source=source_from_path(bad_copy, "synthetic"))
    assert src_bad.status == "tamper_detected" and src_bad.causes == ["SOURCE_DATA_MODIFIED"]


def test_gas_is_constant_across_batch_sizes_on_real_chain(live):
    cfg, chain, index = live
    # The first-ever anchor on a fresh contract also initialises batchCount (0 -> 1), which
    # costs more than later increments, so warm up before comparing steady-state calls.
    chain.anchor_batch(b"\x07" * 32, "warmup", 1, 30)
    gas = []
    for n in (1, 10, 100):
        sub = replace(cfg, batch_size=n)
        collect_synthetic(index, n, cfg.source_dir)
        gas.append(anchor_pending(index, chain, sub)[0].gas_used)
    assert max(gas) - min(gas) < 2_000, gas


def test_unlisted_key_cannot_anchor(live):
    cfg, chain, _ = live
    artifact = load_artifact(cfg.artifact_path)
    outsider = Web3ChainClient(cfg.rpc_url, chain.contract_address, artifact["abi"], ANVIL_ACCOUNT_2_KEY)
    with pytest.raises(ChainError):
        outsider.anchor_batch(b"\x01" * 32, "aegis", 1, 30)


def test_unknown_batch_returns_none(live):
    _, chain, _ = live
    assert chain.get_batch(10**9) is None and chain.get_batch(0) is None


def test_demo_passes_on_real_chain(live):
    cfg, chain, _ = live
    lines = []
    assert run_demo(cfg, chain, count=20, out=lines.append)["ok"]
    assert any("tx hash" in line for line in lines)
