import pytest

from ledger.anchorer import anchor_pending
from ledger.collector import collect_synthetic
from ledger.config import Config
from ledger.store import Index
from tests.fakes import FakeChain


@pytest.fixture
def cfg(tmp_path):
    return Config(data_dir=str(tmp_path), batch_size=100).validate()


@pytest.fixture
def index(cfg):
    idx = Index(cfg.database)
    yield idx
    idx.close()


@pytest.fixture
def chain():
    return FakeChain()


@pytest.fixture
def anchored(cfg, index, chain):
    """25 synthetic Aegis records, collected and anchored on the fake chain."""
    col = collect_synthetic(index, 25, cfg.source_dir)
    results = anchor_pending(index, chain, cfg)
    return {"collect": col, "result": results[0], "batch_id": results[0].local_batch_id}
