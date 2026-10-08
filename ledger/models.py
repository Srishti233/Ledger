"""Plain dataclasses shared across Ledger."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class NewRecord:
    source: str  # aegis | gauntlet | synthetic
    kind: str  # audit_entry | report | finding
    ref: str
    canonical: str  # canonical JSON text (no private content)
    leaf_hash: str  # hex, 64 chars
    locator: str  # where to re-fetch the source data from


@dataclass
class RecordRow:
    id: int
    source: str
    kind: str
    ref: str
    canonical: str
    leaf_hash: str
    locator: str
    status: str
    batch_id: Optional[int]
    position: Optional[int]
    proof: Optional[str]  # JSON text
    collected_at: str


@dataclass
class BatchRow:
    id: int
    chain_batch_id: int
    source_label: str
    merkle_root: str  # hex, 64 chars
    record_count: int
    tx_hash: str
    block_number: int
    block_timestamp: int
    gas_used: int
    contract_address: str
    chain_id: int
    status: str
    created_at: str
    anchored_at: Optional[str]
    anchor_seconds: Optional[float]


@dataclass
class NewBatch:
    chain_batch_id: int
    source_label: str
    merkle_root: str
    record_count: int
    tx_hash: str
    block_number: int
    block_timestamp: int
    gas_used: int
    contract_address: str
    chain_id: int
    anchor_seconds: float


@dataclass
class AnchorReceipt:
    batch_id: int
    tx_hash: str
    block_number: int
    block_timestamp: int
    gas_used: int
    contract_address: str


@dataclass
class OnChainBatch:
    batch_id: int
    merkle_root: str  # hex
    label_hash: str  # hex (sha256 of the source label)
    anchored_by: str
    record_count: int
    timestamp: int
    block_number: int
    contract_address: str
