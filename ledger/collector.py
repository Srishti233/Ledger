"""Collectors: read source data, build canonical records, write them to the index as
``pending``. Collectors never write to Aegis or Gauntlet and never store private
content (Aegis snippets, raw attack text)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterable

from .fixtures.synthetic import make_aegis_rows, make_gauntlet_report
from .hashing import canonical_json, leaf_of_canonical, sha256_hex
from .models import NewRecord
from .sources import (
    BYPASS_KEYS,
    AegisDb,
    aegis_canonical,
    gauntlet_canonicals,
    redact_url,
)
from .store import Index


def to_new_record(canonical: dict, locator: str) -> NewRecord:
    return NewRecord(
        source=canonical["source"],
        kind=canonical["kind"],
        ref=canonical["ref"],
        canonical=canonical_json(canonical),
        leaf_hash=leaf_of_canonical(canonical).hex(),
        locator=locator,
    )


def collect_aegis(index: Index, db_url: str, limit: int | None = None) -> dict:
    """Incrementally read new ``audit_events`` rows (id greater than the last collected)."""
    db = AegisDb(db_url)  # raises SourceUnavailable if unreachable
    try:
        since = index.max_numeric_ref("aegis", "audit_entry")
        rows = db.rows_since(since, limit)
    finally:
        db.close()
    locator = "aegis-db:" + redact_url(db_url)
    recs = [to_new_record(aegis_canonical("aegis", r), locator) for r in rows]
    inserted, skipped = index.add_records(recs)
    return {"source": "aegis", "read": len(rows), "inserted": inserted, "skipped": skipped,
            "since_id": since}


def collect_gauntlet(
    index: Index,
    results_path: str,
    source_dir: str,
    source_name: str = "gauntlet",
    bypass_keys: Iterable[str] = BYPASS_KEYS,
) -> dict:
    """Hash the whole results file plus each bypass finding. The file is cached under
    ``source_dir`` so records can be re-verified offline."""
    path = Path(results_path)
    if not path.is_file():
        from .sources import SourceUnavailable

        raise SourceUnavailable(f"results file not found: {results_path}")
    raw = path.read_bytes()
    canon = gauntlet_canonicals(source_name, raw, bypass_keys)
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    cached = Path(source_dir) / f"gauntlet-{sha256_hex(raw)[:16]}.json"
    if not cached.exists():
        shutil.copyfile(path, cached)
    locator = f"gauntlet-file:{cached}"
    inserted, skipped = index.add_records([to_new_record(c, locator) for c in canon])
    return {"source": source_name, "findings": len(canon) - 1, "inserted": inserted,
            "skipped": skipped, "cached_copy": str(cached)}


def collect_synthetic(
    index: Index, count: int, source_dir: str, kind: str = "aegis", seed: int = 1
) -> dict:
    """Generate ``count`` synthetic records (clearly tagged source='synthetic')."""
    if count < 1:
        raise ValueError("count must be >= 1")
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    if kind == "aegis":
        start = index.max_numeric_ref("synthetic", "audit_entry") + 1
        rows = make_aegis_rows(count, seed=seed, start_id=start)
        snap = Path(source_dir) / f"synthetic-aegis-{start}-{start + count - 1}.json"
        snap.write_text(json.dumps({"format": "aegis-audit-snapshot/1", "source": "synthetic",
                                    "rows": rows}, indent=1))
        locator = f"aegis-snapshot:{snap}"
        recs = [to_new_record(aegis_canonical("synthetic", r), locator) for r in rows]
        inserted, skipped = index.add_records(recs)
        return {"source": "synthetic", "kind": kind, "inserted": inserted,
                "skipped": skipped, "snapshot": str(snap)}
    if kind == "gauntlet":
        report = make_gauntlet_report(count, seed=seed)
        out = Path(source_dir) / f"synthetic-gauntlet-results-{seed}-{count}.json"
        out.write_text(json.dumps(report, indent=1))
        res = collect_gauntlet(index, str(out), source_dir, source_name="synthetic")
        res["kind"] = kind
        return res
    raise ValueError("kind must be 'aegis' or 'gauntlet'")
