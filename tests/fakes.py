"""In-memory ChainClient used by unit tests (the integration tests use real Anvil)."""

from __future__ import annotations

import hashlib
from typing import Optional

from ledger.chain import ChainError
from ledger.models import AnchorReceipt, OnChainBatch


class FakeChain:
    def __init__(self, contract_address: str = "0x" + "ab" * 20, chain_id: int = 31337):
        self.contract_address = contract_address
        self._chain_id = chain_id
        self.batches: list[OnChainBatch] = []
        self.block = 100
        self.connected = True
        self.fail_next_anchor = False
        self.anchor_calls = 0

    def is_connected(self) -> bool:
        return self.connected

    def chain_id(self) -> int:
        return self._chain_id

    def anchor_batch(self, root: bytes, label: str, count: int, timeout: float) -> AnchorReceipt:
        self.anchor_calls += 1
        if not self.connected:
            raise ChainError("not connected")
        if self.fail_next_anchor:
            self.fail_next_anchor = False
            raise ChainError("simulated failure")
        self.block += 1
        batch_id = len(self.batches) + 1
        ts = 1_800_000_000 + self.block
        self.batches.append(OnChainBatch(
            batch_id=batch_id, merkle_root=root.hex(),
            label_hash=hashlib.sha256(label.encode()).hexdigest(),
            anchored_by="0x" + "11" * 20, record_count=count, timestamp=ts,
            block_number=self.block, contract_address=self.contract_address))
        return AnchorReceipt(batch_id, "0x" + hashlib.sha256(root).hexdigest(), self.block, ts,
                             98_765, self.contract_address)

    def get_batch(self, batch_id: int) -> Optional[OnChainBatch]:
        if not self.connected:
            raise ChainError("not connected")
        return self.batches[batch_id - 1] if 1 <= batch_id <= len(self.batches) else None

    def wait_confirmations(self, receipt, needed, timeout) -> None:
        return None
