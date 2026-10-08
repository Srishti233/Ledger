"""Ledger's local SQLite index.

This is a convenience index (leaf -> batch -> tx -> block). It is NOT a source of
truth: the verifier always re-checks it against the chain.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from .models import BatchRow, NewBatch, NewRecord, RecordRow

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_batch_id INTEGER NOT NULL,
    source_label TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_timestamp INTEGER NOT NULL,
    gas_used INTEGER NOT NULL,
    contract_address TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    anchored_at TEXT,
    anchor_seconds REAL
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    canonical TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    locator TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    batch_id INTEGER REFERENCES batches(id),
    position INTEGER,
    proof TEXT,
    collected_at TEXT NOT NULL,
    UNIQUE (source, kind, ref)
);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
CREATE INDEX IF NOT EXISTS idx_records_batch ON records(batch_id);
"""


def archive_stale_index(path: str | Path) -> str | None:
    """Move an index whose chain no longer exists out of the way (dev chains only).

    Used when a local dev chain was reset (e.g. ``docker compose down``) but Ledger's data
    volume survived: the old batches are gone from the new chain, and leaving them in the
    index would make every old record look tampered. The old file is kept, not deleted.
    Returns the new path, or None if there was nothing to archive.
    """
    p = Path(path)
    if str(path) == ":memory:" or not p.exists():
        return None
    conn = sqlite3.connect(str(p))
    try:
        has = conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    except sqlite3.DatabaseError:
        has = 0
    finally:
        conn.close()
    if not has:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = p.with_name(f"{p.name}.stale-{stamp}")
    p.rename(dest)
    return str(dest)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Index:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- records -------------------------------------------------------
    def add_records(self, recs: Sequence[NewRecord]) -> tuple[int, int]:
        """Insert pending records. Returns (inserted, skipped_duplicates)."""
        inserted = 0
        now = utcnow()
        with self._lock:
            for r in recs:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO records "
                    "(source, kind, ref, canonical, leaf_hash, locator, status, collected_at) "
                    "VALUES (?,?,?,?,?,?, 'pending', ?)",
                    (r.source, r.kind, r.ref, r.canonical, r.leaf_hash, r.locator, now),
                )
                inserted += cur.rowcount
            self._conn.commit()
        return inserted, len(recs) - inserted

    @staticmethod
    def _rec(row: sqlite3.Row) -> RecordRow:
        return RecordRow(**{k: row[k] for k in row.keys()})

    def get_record(self, record_id: int) -> Optional[RecordRow]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return self._rec(row) if row else None

    def pending(self, source: str | None = None, limit: int | None = None) -> list[RecordRow]:
        sql = "SELECT * FROM records WHERE status='pending'"
        args: list = []
        if source:
            sql += " AND source=?"
            args.append(source)
        sql += " ORDER BY id"
        if limit:
            sql += " LIMIT ?"
            args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._rec(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM records GROUP BY status"
            ).fetchall()
        out = {"pending": 0, "anchored": 0}
        out.update({r["status"]: r["n"] for r in rows})
        return out

    def max_numeric_ref(self, source: str, kind: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(CAST(ref AS INTEGER)) AS m FROM records WHERE source=? AND kind=?",
                (source, kind),
            ).fetchone()
        return int(row["m"] or 0)

    def batch_records(self, batch_id: int) -> list[RecordRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM records WHERE batch_id=? ORDER BY position, id", (batch_id,)
            ).fetchall()
        return [self._rec(r) for r in rows]

    # ---- batches -------------------------------------------------------
    @staticmethod
    def _batch(row: sqlite3.Row) -> BatchRow:
        return BatchRow(**{k: row[k] for k in row.keys()})

    def record_anchor(
        self, batch: NewBatch, record_ids: Sequence[int], proofs: Sequence[str]
    ) -> int:
        """Atomically store a mined batch and mark its records anchored."""
        if len(record_ids) != len(proofs):
            raise ValueError("record_ids and proofs must be the same length")
        now = utcnow()
        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO batches (chain_batch_id, source_label, merkle_root, record_count,"
                    " tx_hash, block_number, block_timestamp, gas_used, contract_address, chain_id,"
                    " status, created_at, anchored_at, anchor_seconds)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?, 'anchored', ?, ?, ?)",
                    (
                        batch.chain_batch_id, batch.source_label, batch.merkle_root,
                        batch.record_count, batch.tx_hash, batch.block_number,
                        batch.block_timestamp, batch.gas_used, batch.contract_address,
                        batch.chain_id, now, now, batch.anchor_seconds,
                    ),
                )
                local_id = int(cur.lastrowid)
                for pos, (rid, proof) in enumerate(zip(record_ids, proofs)):
                    self._conn.execute(
                        "UPDATE records SET status='anchored', batch_id=?, position=?, proof=?"
                        " WHERE id=?",
                        (local_id, pos, proof, rid),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return local_id

    def get_batch(self, batch_id: int) -> Optional[BatchRow]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
        return self._batch(row) if row else None

    def list_batches(self, limit: int = 20) -> list[BatchRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM batches ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._batch(r) for r in rows]

    def totals(self) -> dict:
        with self._lock:
            b = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(gas_used),0) AS gas,"
                " COALESCE(SUM(anchor_seconds),0.0) AS secs, MAX(anchored_at) AS last,"
                " (SELECT anchor_seconds FROM batches ORDER BY id DESC LIMIT 1) AS last_secs"
                " FROM batches"
            ).fetchone()
            total = self._conn.execute("SELECT COUNT(*) AS n FROM records").fetchone()["n"]
        return {
            "records_total": int(total),
            "batches": int(b["n"]),
            "gas_total": int(b["gas"]),
            "anchor_seconds_sum": float(b["secs"]),
            "last_anchor_at": b["last"],
            "last_anchor_seconds": b["last_secs"],
        }
