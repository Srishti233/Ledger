"""Service layer shared by the CLI and the HTTP API."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Optional

from .anchorer import AnchorResult, anchor_pending
from .chain import ChainClient
from .collector import collect_aegis, collect_gauntlet, collect_synthetic
from .config import Config
from .merkle import proof_from_json, root_from_proof
from .sources import Source
from .store import Index
from .verifier import Verdict, Verifier


class LedgerService:
    def __init__(self, cfg: Config, index: Index, chain: ChainClient):
        self.cfg, self.index, self.chain = cfg, index, chain
        self.verifier = Verifier(index, chain, cfg)
        self._anchor_lock = threading.Lock()

    # ---- collect -------------------------------------------------------
    def collect_aegis(self, db_url: str | None = None, limit: int | None = None) -> dict:
        url = db_url or self.cfg.aegis_db_url
        if not url:
            raise ValueError("no Aegis database URL: pass --db-url or set aegis_db_url")
        return collect_aegis(self.index, url, limit)

    def collect_gauntlet(self, results_path: str, bypass_keys: Optional[list[str]] = None) -> dict:
        kwargs = {"bypass_keys": bypass_keys} if bypass_keys else {}
        return collect_gauntlet(self.index, results_path, self.cfg.source_dir, **kwargs)

    def collect_synthetic(self, count: int, kind: str = "aegis", seed: int = 1) -> dict:
        return collect_synthetic(self.index, count, self.cfg.source_dir, kind, seed)

    # ---- anchor --------------------------------------------------------
    def anchor_now(self) -> list[AnchorResult]:
        with self._anchor_lock:
            return anchor_pending(self.index, self.chain, self.cfg)

    def anchor_if_due(self) -> list[AnchorResult]:
        with self._anchor_lock:
            return anchor_pending(self.index, self.chain, self.cfg, only_if_due=True)

    # ---- read ----------------------------------------------------------
    def record(self, record_id: int) -> dict:
        rec = self.index.get_record(record_id)
        if rec is None:
            raise LookupError(f"record {record_id} not found")
        out = {"id": rec.id, "source": rec.source, "kind": rec.kind, "ref": rec.ref,
               "status": rec.status, "leaf_hash": rec.leaf_hash,
               "record": json.loads(rec.canonical), "position": rec.position,
               "collected_at": rec.collected_at, "batch": None}
        if rec.batch_id:
            b = self.index.get_batch(rec.batch_id)
            if b:
                out["batch"] = self.batch_dict(b.id)
        return out

    def proof(self, record_id: int) -> dict:
        rec = self.index.get_record(record_id)
        if rec is None:
            raise LookupError(f"record {record_id} not found")
        if rec.status != "anchored" or not rec.proof or not rec.batch_id:
            raise LookupError(f"record {record_id} is not anchored yet")
        b = self.index.get_batch(rec.batch_id)
        steps = proof_from_json(json.loads(rec.proof))
        return {"record_id": rec.id, "leaf_hash": rec.leaf_hash, "proof": json.loads(rec.proof),
                "merkle_root": b.merkle_root, "chain_batch_id": b.chain_batch_id,
                "tx_hash": b.tx_hash, "block_number": b.block_number,
                "contract_address": b.contract_address,
                "recomputed_root": root_from_proof(bytes.fromhex(rec.leaf_hash), steps).hex(),
                "how_to_check": "recompute the leaf from the record, fold it with the sibling "
                "hashes (sorted-pair SHA-256, node prefix 0x01), and compare the result with "
                "getBatch(chain_batch_id).merkleRoot on the contract."}

    def batch_dict(self, local_id: int) -> dict:
        b = self.index.get_batch(local_id)
        if b is None:
            raise LookupError(f"batch {local_id} not found")
        return {"id": b.id, "chain_batch_id": b.chain_batch_id, "source_label": b.source_label,
                "merkle_root": b.merkle_root, "record_count": b.record_count, "tx_hash": b.tx_hash,
                "block_number": b.block_number,
                "block_time_utc": datetime.fromtimestamp(b.block_timestamp, tz=timezone.utc).isoformat(),
                "gas_used": b.gas_used, "contract_address": b.contract_address,
                "chain_id": b.chain_id, "status": b.status, "anchor_seconds": b.anchor_seconds,
                "explorer_url": self.explorer_url(b.tx_hash)}

    def batches(self, limit: int = 20) -> list[dict]:
        return [self.batch_dict(b.id) for b in self.index.list_batches(limit)]

    def explorer_url(self, tx_hash: str) -> str:
        pattern = self.cfg.explorer_tx_url
        return pattern.replace("{tx_hash}", tx_hash) if pattern.startswith(("http://", "https://")) else ""

    # ---- verify --------------------------------------------------------
    def verify_record(self, record_id: int, source: Optional[Source] = None,
                      use_source: bool = True) -> Verdict:
        return self.verifier.verify_record(record_id, source, use_source)

    def verify_batch(self, batch_id: int, source: Optional[Source] = None,
                     use_source: bool = False) -> Verdict:
        return self.verifier.verify_batch(batch_id, source, use_source)

    # ---- status / metrics ----------------------------------------------
    def status(self) -> dict:
        counts = self.index.count_by_status()
        totals = self.index.totals()
        try:
            connected = bool(self.chain.is_connected())
        except Exception:
            connected = False
        return {"pending": counts["pending"], "anchored": counts["anchored"],
                "batches": totals["batches"], "last_anchor_at": totals["last_anchor_at"],
                "chain": {"connected": connected, "rpc_url": self.cfg.rpc_url,
                          "local": self.cfg.is_local_chain(),
                          "contract_address": self.chain.contract_address},
                "batch_size": self.cfg.batch_size, "max_wait_seconds": self.cfg.max_wait_seconds,
                "confirmations": self.cfg.confirmations}

    def metrics_text(self) -> str:
        counts, t = self.index.count_by_status(), self.index.totals()
        collected = counts["pending"] + counts["anchored"]
        lines = [
            ("ledger_records_collected_total", "counter", "Records collected into the index", collected),
            ("ledger_records_anchored_total", "counter", "Records anchored on-chain", counts["anchored"]),
            ("ledger_records_pending", "gauge", "Records waiting to be anchored", counts["pending"]),
            ("ledger_batches_anchored_total", "counter", "Batches anchored on-chain", t["batches"]),
            ("ledger_gas_spent_total", "counter", "Gas used by anchorBatch transactions", t["gas_total"]),
            ("ledger_anchor_latency_seconds_sum", "counter", "Sum of anchor latencies", t["anchor_seconds_sum"]),
            ("ledger_anchor_latency_seconds_count", "counter", "Number of timed anchors", t["batches"]),
            ("ledger_last_anchor_latency_seconds", "gauge", "Latency of the most recent anchor",
             t["last_anchor_seconds"] or 0),
        ]
        out = []
        for name, kind, help_, value in lines:
            out += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}", f"{name} {value}"]
        return "\n".join(out) + "\n"
