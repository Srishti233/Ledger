"""Canonical JSON and hashing helpers shared by collectors, sources and verifier."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .merkle import leaf_hash

RECORD_VERSION = 1


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_ts(value: Any) -> str:
    """Normalise a timestamp (datetime or string) to UTC ISO-8601 so that a value
    read from Postgres, SQLite or a JSON snapshot hashes identically."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    else:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def make_canonical(source: str, kind: str, ref: str, payload: dict) -> dict:
    """The exact structure whose hash becomes a Merkle leaf."""
    return {"v": RECORD_VERSION, "source": source, "kind": kind, "ref": ref, "payload": payload}


def leaf_of_canonical(canonical: dict | str) -> bytes:
    text = canonical if isinstance(canonical, str) else canonical_json(canonical)
    return leaf_hash(text.encode("utf-8"))
