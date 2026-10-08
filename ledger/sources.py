"""Source adapters: turn Aegis / Gauntlet data into canonical records, and re-fetch them.

A *canonical record* is the small JSON object whose hash is the Merkle leaf. It never
contains private content: no Aegis snippets, no raw Gauntlet attack text (that is
hashed, not stored).

Assumption about Gauntlet: its ``results.json`` schema is not available to this
project. Bypass findings are read from any list found under one of ``BYPASS_KEYS``;
each item needs ``attack_id`` and ``variant_text`` plus ``target_name`` (or ``target``).
Adjust ``BYPASS_KEYS`` (or pass ``--bypass-key``) if your results file differs.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol
from urllib.parse import urlparse, urlunparse

from .hashing import make_canonical, normalize_ts, sha256_hex
from .models import RecordRow

BYPASS_KEYS = ("bypasses", "successful_bypasses", "findings", "misses", "evasions")
AEGIS_COLUMNS = ("id", "timestamp", "direction", "decision", "entry_hash")


class SourceUnavailable(RuntimeError):
    """The source data cannot be reached or read right now."""


# ---- canonical builders ------------------------------------------------------
def aegis_canonical(source: str, row: dict) -> dict:
    missing = [c for c in AEGIS_COLUMNS if c not in row or row[c] is None]
    if missing:
        raise ValueError(f"Aegis row is missing columns: {', '.join(missing)}")
    payload = {
        "id": int(row["id"]),
        "timestamp": normalize_ts(row["timestamp"]),
        "direction": str(row["direction"]),
        "decision": str(row["decision"]),
        "entry_hash": str(row["entry_hash"]),
    }
    return make_canonical(source, "audit_entry", str(payload["id"]), payload)


def _walk_bypass_lists(node: Any, keys: Iterable[str]) -> Iterable[dict]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys and isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        yield item
            else:
                yield from _walk_bypass_lists(v, keys)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_bypass_lists(v, keys)


def extract_findings(doc: Any, bypass_keys: Iterable[str] = BYPASS_KEYS) -> list[dict]:
    """Return unique ``{attack_id, target_name, variant_sha256}`` dicts, in order."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for item in _walk_bypass_lists(doc, tuple(bypass_keys)):
        attack_id = item.get("attack_id")
        text = item.get("variant_text")
        target = item.get("target_name", item.get("target"))
        if attack_id is None or text is None or target is None:
            continue
        finding = {
            "attack_id": str(attack_id),
            "target_name": str(target),
            "variant_sha256": sha256_hex(str(text).encode("utf-8")),
        }
        key = (finding["attack_id"], finding["target_name"], finding["variant_sha256"])
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out


def finding_ref(f: dict) -> str:
    return f"{f['attack_id']}|{f['target_name']}|{f['variant_sha256'][:16]}"


def gauntlet_canonicals(
    source: str, raw: bytes, bypass_keys: Iterable[str] = BYPASS_KEYS
) -> list[dict]:
    """Canonical records for a whole results file: one report record + one per finding."""
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"results file is not valid JSON: {exc}") from exc
    digest = sha256_hex(raw)
    out = [make_canonical(source, "report", digest, {"results_sha256": digest})]
    for f in extract_findings(doc, bypass_keys):
        out.append(make_canonical(source, "finding", finding_ref(f), f))
    return out


# ---- Aegis database access (read-only) ---------------------------------------
def redact_url(url: str) -> str:
    """Strip credentials from a DB URL before it is stored as a locator."""
    p = urlparse(url)
    if p.password is None and p.username is None:
        return url
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return urlunparse(p._replace(netloc=host))


class AegisDb:
    """Read-only access to Aegis's ``audit_events`` table (Postgres or SQLite)."""

    def __init__(self, url: str):
        self.url = url
        self._kind = "sqlite" if url.startswith("sqlite:") else "postgres"
        try:
            if self._kind == "sqlite":
                path = url.split("sqlite:///", 1)[1] if "sqlite:///" in url else url[7:]
                if not Path(path).exists():
                    raise SourceUnavailable(f"SQLite file not found: {path}")
                self._conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                self._conn.row_factory = sqlite3.Row
                self._ph = "?"
            else:
                try:
                    import psycopg  # type: ignore
                    from psycopg.rows import dict_row  # type: ignore
                except ImportError as exc:
                    raise SourceUnavailable(
                        "psycopg is not installed; run: pip install 'ledger[postgres]'"
                    ) from exc
                self._conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=5)
                self._conn.read_only = True
                self._ph = "%s"
        except SourceUnavailable:
            raise
        except Exception as exc:
            raise SourceUnavailable(f"cannot connect to Aegis database: {exc}") from exc

    def _query(self, sql: str, args: tuple = ()) -> list[dict]:
        try:
            cur = self._conn.cursor()
            cur.execute(sql, args)
            return [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            raise SourceUnavailable(f"Aegis audit_events query failed: {exc}") from exc

    def rows_since(self, since_id: int = 0, limit: int | None = None) -> list[dict]:
        cols = ", ".join(AEGIS_COLUMNS)
        sql = f"SELECT {cols} FROM audit_events WHERE id > {self._ph} ORDER BY id"
        args: tuple = (since_id,)
        if limit:
            sql += f" LIMIT {self._ph}"
            args = (since_id, limit)
        return self._query(sql, args)

    def row(self, row_id: int) -> Optional[dict]:
        cols = ", ".join(AEGIS_COLUMNS)
        rows = self._query(f"SELECT {cols} FROM audit_events WHERE id = {self._ph}", (row_id,))
        return rows[0] if rows else None

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ---- verification-time sources -----------------------------------------------
class Source(Protocol):
    def lookup(self, rec: RecordRow) -> Optional[dict]:
        """Return the canonical record recomputed from source data, or None if the
        source no longer has it. Raise SourceUnavailable if the source can't be read."""


class AegisSnapshotSource:
    """A JSON export of the audit table: a list of rows, or
    ``{"format": ..., "source": ..., "rows": [...]}``."""

    def __init__(self, path: str, source_name: str | None = None):
        self.path = path
        try:
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise SourceUnavailable(f"cannot read snapshot {path}: {exc}") from exc
        if isinstance(data, dict):
            rows = data.get("rows", [])
            self.source_name = source_name or data.get("source", "aegis")
        else:
            rows, self.source_name = data, source_name or "aegis"
        self._rows = {int(r["id"]): r for r in rows if isinstance(r, dict) and "id" in r}

    def lookup(self, rec: RecordRow) -> Optional[dict]:
        if rec.kind != "audit_entry":
            return None
        row = self._rows.get(int(rec.ref))
        return aegis_canonical(rec.source, row) if row else None


class AegisDbSource:
    def __init__(self, url: str):
        self.db = AegisDb(url)

    def lookup(self, rec: RecordRow) -> Optional[dict]:
        if rec.kind != "audit_entry":
            return None
        row = self.db.row(int(rec.ref))
        return aegis_canonical(rec.source, row) if row else None


class GauntletFileSource:
    def __init__(self, path: str, bypass_keys: Iterable[str] = BYPASS_KEYS):
        self.path = path
        self._bypass_keys = tuple(bypass_keys)
        self._cache: dict[str, dict[tuple, dict]] = {}
        try:
            self._raw = Path(path).read_bytes()
        except OSError as exc:
            raise SourceUnavailable(f"cannot read results file {path}: {exc}") from exc

    def lookup(self, rec: RecordRow) -> Optional[dict]:
        canon = self._cache.get(rec.source)
        if canon is None:
            try:
                items = gauntlet_canonicals(rec.source, self._raw, self._bypass_keys)
            except ValueError as exc:
                raise SourceUnavailable(str(exc)) from exc
            canon = {(c["kind"], c["ref"]): c for c in items}
            self._cache[rec.source] = canon
        return canon.get((rec.kind, rec.ref))


def source_from_path(path: str, source_name: str | None = None) -> Source:
    """Build a Source from a file path, auto-detecting snapshot vs Gauntlet results."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceUnavailable(f"cannot read {path}: {exc}") from exc
    if isinstance(data, list) or (isinstance(data, dict) and "rows" in data):
        return AegisSnapshotSource(path, source_name)
    return GauntletFileSource(path)


def build_source(locator: str, aegis_db_url: str = "") -> Source:
    """Re-open the source a record came from, using its stored locator."""
    kind, _, target = locator.partition(":")
    if kind == "aegis-snapshot":
        return AegisSnapshotSource(target)
    if kind == "gauntlet-file":
        return GauntletFileSource(target)
    if kind == "aegis-db":
        return AegisDbSource(aegis_db_url or target)
    raise SourceUnavailable(f"unknown source locator {locator!r}")
