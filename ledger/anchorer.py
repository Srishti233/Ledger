"""Batcher + anchorer: pending records -> Merkle tree -> one on-chain transaction."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .chain import ChainClient, ChainError
from .config import Config
from .merkle import MerkleTree, proof_to_json
from .models import NewBatch, RecordRow
from .store import Index
import json


class AnchorError(RuntimeError):
    pass


@dataclass
class AnchorResult:
    local_batch_id: int
    chain_batch_id: int
    source_label: str
    record_count: int
    merkle_root: str
    tx_hash: str
    block_number: int
    gas_used: int
    anchor_seconds: float

    def to_dict(self) -> dict:
        return asdict(self)


def label_for(rec: RecordRow) -> str:
    """Batch label: one source family per batch so a batch can be re-fetched from one place."""
    if rec.source == "synthetic":
        return "synthetic-aegis" if rec.kind == "audit_entry" else "synthetic-gauntlet"
    return rec.source


def _anchor_chunk(
    index: Index, chain: ChainClient, cfg: Config, label: str, chunk: list[RecordRow]
) -> AnchorResult:
    started = time.perf_counter()
    tree = MerkleTree([bytes.fromhex(r.leaf_hash) for r in chunk])
    try:
        receipt = chain.anchor_batch(tree.root, label, len(chunk), cfg.tx_timeout_seconds)
        chain.wait_confirmations(receipt, cfg.confirmations, cfg.tx_timeout_seconds)
    except ChainError as exc:
        raise AnchorError(str(exc)) from exc
    elapsed = time.perf_counter() - started
    proofs = [json.dumps(proof_to_json(tree.proof(i))) for i in range(len(chunk))]
    chain_id = chain.chain_id()
    local_id = index.record_anchor(
        NewBatch(
            chain_batch_id=receipt.batch_id,
            source_label=label,
            merkle_root=tree.root.hex(),
            record_count=len(chunk),
            tx_hash=receipt.tx_hash,
            block_number=receipt.block_number,
            block_timestamp=receipt.block_timestamp,
            gas_used=receipt.gas_used,
            contract_address=receipt.contract_address,
            chain_id=chain_id,
            anchor_seconds=elapsed,
        ),
        [r.id for r in chunk],
        proofs,
    )
    return AnchorResult(local_id, receipt.batch_id, label, len(chunk), tree.root.hex(),
                        receipt.tx_hash, receipt.block_number, receipt.gas_used, elapsed)


def _due(group: list[RecordRow], cfg: Config, now: datetime) -> bool:
    if len(group) >= cfg.batch_size:
        return True
    oldest = min(datetime.fromisoformat(r.collected_at) for r in group)
    return (now - oldest).total_seconds() >= cfg.max_wait_seconds


def anchor_pending(
    index: Index,
    chain: ChainClient,
    cfg: Config,
    only_if_due: bool = False,
    now: Optional[datetime] = None,
    on_result: Optional[Callable[[AnchorResult], None]] = None,
) -> list[AnchorResult]:
    """Anchor pending records, one batch per source label, chunked by ``batch_size``.

    With ``only_if_due`` a label's records are anchored only when a full batch has
    accumulated or the oldest has waited ``max_wait_seconds`` (used by the background
    loop). Without it (``ledger anchor-now``) everything pending is anchored.

    Crash window: if the process dies after a transaction is mined but before the index
    is updated, those records stay ``pending`` and are anchored again later. That creates
    a harmless duplicate batch on-chain, never a missed record.
    """
    now = now or datetime.now(timezone.utc)
    groups: dict[str, list[RecordRow]] = {}
    for rec in index.pending():
        groups.setdefault(label_for(rec), []).append(rec)
    results: list[AnchorResult] = []
    for label in sorted(groups):
        group = groups[label]
        if only_if_due and not _due(group, cfg, now):
            continue
        for i in range(0, len(group), cfg.batch_size):
            res = _anchor_chunk(index, chain, cfg, label, group[i : i + cfg.batch_size])
            results.append(res)
            if on_result:
                on_result(res)
    return results
