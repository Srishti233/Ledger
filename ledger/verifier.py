"""Verification: local index vs. the live chain vs. (optionally) the source data.

The decision logic is in pure functions (``evaluate_record`` / ``evaluate_batch``) that
take already-fetched data, so tamper detection is testable with no chain or network.
``Verifier`` wires them to the index, chain client and sources.

Key idea: the ONLY trusted input is the on-chain root. Everything Ledger stored locally
(leaves, proofs, roots) is re-checked against it, and a record's *source* data is
re-hashed and checked against the same anchored root through the stored proof.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .chain import ChainClient, ChainError
from .config import Config
from .hashing import leaf_of_canonical
from .merkle import MerkleTree, MerkleError, proof_from_json, verify_inclusion
from .models import BatchRow, OnChainBatch, RecordRow
from .sources import Source, SourceUnavailable, build_source
from .store import Index

VERIFIED = "verified"
TAMPER = "tamper_detected"
INCONCLUSIVE = "inconclusive"

WHAT_PROVES = (
    "Anchoring a hash on-chain proves: (a) this exact hash existed no later than block N, "
    "with a timestamp derived from that block, and (b) nobody can alter the anchored hash "
    "afterwards without it being obvious, because changing one historical block would break "
    "the chain's own hash-linking, which anyone running a node can check independently."
)
WHAT_NOT_PROVES = (
    "It does NOT prove that the underlying data (an Aegis audit row, a Gauntlet report) was "
    "captured correctly, that Ledger did not anchor a wrong hash to begin with, that the "
    "anchoring key belongs to the real Aegis or Gauntlet instance, or anything about the "
    "real-world truth of what the log claims happened."
)

CAUSE_TEXT = {
    "LEDGER_INDEX_MODIFIED": "Ledger's local index no longer matches what was anchored on-chain "
    "(simulates a compromised Ledger server). The chain, not the index, is authoritative.",
    "SOURCE_DATA_MODIFIED": "The source data no longer hashes to the leaf that was anchored: the "
    "source (e.g. the Aegis audit table) was changed after anchoring. The on-chain root is intact.",
    "SOURCE_RECORD_MISSING": "The source no longer contains this record.",
    "ONCHAIN_ROOT_MISMATCH": "The root stored in Ledger's index differs from the root on-chain.",
    "CHAIN_METADATA_MISMATCH": "Batch metadata in Ledger's index (contract, count, label or "
    "block) differs from what the chain reports.",
    "BATCH_NOT_ON_CHAIN": "The chain has no such batch (wrong chain/contract, or the index is wrong).",
    "RECORD_SET_INCOMPLETE": "The record set in the index is incomplete or has gaps/extra rows "
    "compared with what was anchored.",
}


@dataclass
class Check:
    name: str
    status: str  # pass | fail | skipped
    detail: str


@dataclass
class SourceResult:
    checked: bool
    canonical: Optional[dict] = None
    note: str = ""


@dataclass
class Verdict:
    scope: str
    status: str
    checks: list[Check] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)
    index_culprits: list[int] = field(default_factory=list)
    source_culprits: list[int] = field(default_factory=list)
    chain: dict = field(default_factory=dict)
    source_checked: bool = False
    proven: list[str] = field(default_factory=list)
    not_proven: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "status": self.status,
            "source_checked": self.source_checked,
            "checks": [c.__dict__ for c in self.checks],
            "causes": [{"code": c, "meaning": CAUSE_TEXT[c]} for c in self.causes],
            "index_culprit_record_ids": self.index_culprits,
            "source_culprit_record_ids": self.source_culprits,
            "chain": self.chain,
            "what_was_proven": self.proven,
            "what_was_not_proven": self.not_proven,
            "limitation": WHAT_PROVES + " " + WHAT_NOT_PROVES,
        }

    @property
    def exit_code(self) -> int:
        return {VERIFIED: 0, TAMPER: 1}.get(self.status, 2)

    def render_text(self) -> str:
        icon = {VERIFIED: "VERIFIED", TAMPER: "TAMPER DETECTED", INCONCLUSIVE: "INCONCLUSIVE"}
        lines = [f"== {self.scope}: {icon[self.status]} =="]
        for c in self.checks:
            mark = {"pass": "[ok]  ", "fail": "[FAIL]", "skipped": "[skip]"}[c.status]
            lines.append(f"  {mark} {c.name}: {c.detail}")
        if self.causes:
            lines.append("  Diagnosis:")
            for c in self.causes:
                lines.append(f"    - {c}: {CAUSE_TEXT[c]}")
        if self.index_culprits:
            lines.append(f"  Records whose index entry fails against the chain: {self.index_culprits}")
        if self.source_culprits:
            lines.append(f"  Records whose source data no longer matches the anchor: {self.source_culprits}")
        lines.append("  What was proven:")
        lines += [f"    + {p}" for p in self.proven] or ["    (nothing)"]
        lines.append("  What was NOT proven / not checked:")
        lines += [f"    - {p}" for p in self.not_proven]
        return "\n".join(lines)


# ---- pure helpers ------------------------------------------------------------
def _hex_bytes(value: str) -> Optional[bytes]:
    try:
        b = bytes.fromhex(value)
    except (ValueError, TypeError):
        return None
    return b if len(b) == 32 else None


def _stored_proof(rec: RecordRow):
    try:
        return proof_from_json(json.loads(rec.proof)) if rec.proof is not None else None
    except (ValueError, KeyError, TypeError, MerkleError):
        return None


def label_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@dataclass
class RecordFinding:
    record_id: int
    leaf_consistent: bool
    proof_valid: bool
    source: str  # not_checked | matches | missing | modified

    @property
    def index_ok(self) -> bool:
        return self.leaf_consistent and self.proof_valid


def classify_record(rec: RecordRow, chain_root: bytes, src: SourceResult) -> RecordFinding:
    stored = _hex_bytes(rec.leaf_hash)
    proof = _stored_proof(rec)
    leaf_ok = False
    if stored is not None:
        try:
            leaf_ok = leaf_of_canonical(rec.canonical) == stored
        except (TypeError, ValueError):
            leaf_ok = False
    proof_ok = bool(stored is not None and proof is not None
                    and verify_inclusion(stored, proof, chain_root))
    source = "not_checked"
    if src.checked:
        if src.canonical is None:
            source = "missing"
        else:
            fresh = leaf_of_canonical(src.canonical)
            ok = proof is not None and verify_inclusion(fresh, proof, chain_root)
            source = "matches" if ok else "modified"
    return RecordFinding(rec.id, leaf_ok, proof_ok, source)


def _chain_meta_problems(batch: BatchRow, onchain: OnChainBatch) -> list[str]:
    problems = []
    if onchain.contract_address.lower() != batch.contract_address.lower():
        problems.append(f"contract {batch.contract_address} (index) vs {onchain.contract_address} (client)")
    if onchain.record_count != batch.record_count:
        problems.append(f"record count {batch.record_count} (index) vs {onchain.record_count} (chain)")
    if onchain.label_hash != label_hash(batch.source_label):
        problems.append("source label hash differs")
    if onchain.block_number != batch.block_number:
        problems.append(f"block {batch.block_number} (index) vs {onchain.block_number} (chain)")
    return problems


def _chain_info(onchain: Optional[OnChainBatch]) -> dict:
    if not onchain:
        return {}
    return {"chain_batch_id": onchain.batch_id, "merkle_root": onchain.merkle_root,
            "block_number": onchain.block_number, "block_time_utc": _fmt_ts(onchain.timestamp),
            "anchored_by": onchain.anchored_by, "record_count": onchain.record_count,
            "contract": onchain.contract_address}


def _finish(v: Verdict, source_note: Optional[str]) -> Verdict:
    failed = any(c.status == "fail" for c in v.checks)
    chain_skipped = any(c.name == "chain_lookup" and c.status == "skipped" for c in v.checks)
    v.status = TAMPER if failed else (INCONCLUSIVE if chain_skipped else VERIFIED)
    if v.status == VERIFIED and v.chain:
        v.proven.append(
            f"the anchored leaf is included in Merkle root {v.chain['merkle_root'][:16]}..., which "
            f"was written on-chain in block {v.chain['block_number']} at {v.chain['block_time_utc']} "
            f"by {v.chain['anchored_by']}; this exact hash therefore existed no later than then."
        )
        v.proven.append("the root in Ledger's index equals the root read live from the chain.")
    if v.status == TAMPER and v.chain:
        v.proven.append(
            f"the on-chain root (block {v.chain['block_number']}, {v.chain['block_time_utc']}) is the "
            "authoritative reference, and the checks marked FAIL disagree with it."
        )
    if source_note:
        v.not_proven.append(source_note)
    v.not_proven.append("whether the original data was captured correctly or is true in the real world.")
    v.not_proven.append("that the anchoring key belongs to the real Aegis/Gauntlet instance.")
    if v.status == INCONCLUSIVE:
        v.not_proven.append("anything about the chain: it could not be queried, so this is NOT a pass.")
    return v


def evaluate_record(
    rec: RecordRow,
    batch: BatchRow,
    onchain: Optional[OnChainBatch],
    chain_error: str,
    src: SourceResult,
) -> Verdict:
    v = Verdict(scope=f"record {rec.id}", status=INCONCLUSIVE, source_checked=src.checked,
                chain=_chain_info(onchain))
    causes: list[str] = []
    stored_leaf = _hex_bytes(rec.leaf_hash)
    proof = _stored_proof(rec)
    index_root = _hex_bytes(batch.merkle_root)

    local_ok = bool(stored_leaf and proof is not None and index_root
                    and verify_inclusion(stored_leaf, proof, index_root))
    v.checks.append(Check("index_proof_to_index_root", "pass" if local_ok else "fail",
                          "stored leaf + proof reproduce the root stored in the index" if local_ok
                          else "stored leaf + proof do NOT reproduce the root stored in the index"))
    if not local_ok:
        causes.append("LEDGER_INDEX_MODIFIED")

    if onchain is None and chain_error:
        v.checks.append(Check("chain_lookup", "skipped", f"chain unreachable: {chain_error}"))
    elif onchain is None:
        v.checks.append(Check("chain_lookup", "fail", f"batch {batch.chain_batch_id} not found on-chain"))
        causes.append("BATCH_NOT_ON_CHAIN")
    else:
        v.checks.append(Check("chain_lookup", "pass",
                              f"read batch {onchain.batch_id} from the chain (block {onchain.block_number})"))
        chain_root = bytes.fromhex(onchain.merkle_root)
        root_ok = onchain.merkle_root == batch.merkle_root
        v.checks.append(Check("index_root_equals_chain_root", "pass" if root_ok else "fail",
                              "roots match" if root_ok else
                              f"index {batch.merkle_root[:16]}... vs chain {onchain.merkle_root[:16]}..."))
        if not root_ok:
            causes.append("ONCHAIN_ROOT_MISMATCH")
        problems = _chain_meta_problems(batch, onchain)
        v.checks.append(Check("chain_metadata_matches_index", "fail" if problems else "pass",
                              "; ".join(problems) if problems else "contract, count, label and block match"))
        if problems:
            causes.append("CHAIN_METADATA_MISMATCH")
        f = classify_record(rec, chain_root, src)
        v.checks.append(Check("index_leaf_consistent", "pass" if f.leaf_consistent else "fail",
                              "stored record content hashes to the stored leaf" if f.leaf_consistent
                              else "stored record content does NOT hash to the stored leaf"))
        v.checks.append(Check("leaf_included_in_onchain_root", "pass" if f.proof_valid else "fail",
                              "stored leaf + proof reproduce the on-chain root" if f.proof_valid
                              else "stored leaf + proof do NOT reproduce the on-chain root"))
        if not f.index_ok:
            causes.append("LEDGER_INDEX_MODIFIED")
            v.index_culprits.append(rec.id)
        if f.source == "not_checked":
            v.checks.append(Check("source_matches_anchor", "skipped", src.note or "source data not supplied"))
        elif f.source == "matches":
            v.checks.append(Check("source_matches_anchor", "pass",
                                  "leaf recomputed from source data is included in the on-chain root"))
        else:
            v.checks.append(Check("source_matches_anchor", "fail",
                                  "source data no longer matches the anchored leaf" if f.source == "modified"
                                  else "record not found in source data"))
            if f.index_ok:
                causes.append("SOURCE_DATA_MODIFIED" if f.source == "modified" else "SOURCE_RECORD_MISSING")
            v.source_culprits.append(rec.id)
    v.causes = list(dict.fromkeys(causes))
    if src.checked:
        return _finish(v, None)
    return _finish(v, "that the source data still matches (not re-checked: "
                   + (src.note or "not supplied") + ").")


def evaluate_batch(
    batch: BatchRow,
    records: list[RecordRow],
    onchain: Optional[OnChainBatch],
    chain_error: str,
    sources: Optional[dict[int, SourceResult]],
) -> Verdict:
    supplied = sources is not None
    v = Verdict(scope=f"batch {batch.id}", status=INCONCLUSIVE, source_checked=supplied,
                chain=_chain_info(onchain))
    causes: list[str] = []
    if onchain is None and chain_error:
        v.checks.append(Check("chain_lookup", "skipped", f"chain unreachable: {chain_error}"))
        return _finish(v, "anything chain-related.")
    if onchain is None:
        v.checks.append(Check("chain_lookup", "fail", f"batch {batch.chain_batch_id} not found on-chain"))
        v.causes = ["BATCH_NOT_ON_CHAIN"]
        return _finish(v, "that the source data still matches (not re-checked).")
    v.checks.append(Check("chain_lookup", "pass",
                          f"read batch {onchain.batch_id} from the chain (block {onchain.block_number})"))
    chain_root = bytes.fromhex(onchain.merkle_root)

    root_ok = onchain.merkle_root == batch.merkle_root
    v.checks.append(Check("index_root_equals_chain_root", "pass" if root_ok else "fail",
                          "roots match" if root_ok else
                          f"index {batch.merkle_root[:16]}... vs chain {onchain.merkle_root[:16]}..."))
    if not root_ok:
        causes.append("ONCHAIN_ROOT_MISMATCH")
    problems = _chain_meta_problems(batch, onchain)
    v.checks.append(Check("chain_metadata_matches_index", "fail" if problems else "pass",
                          "; ".join(problems) if problems else "contract, count, label and block match"))
    if problems:
        causes.append("CHAIN_METADATA_MISMATCH")

    complete = (len(records) == onchain.record_count
                and [r.position for r in records] == list(range(len(records))))
    v.checks.append(Check("record_set_complete", "pass" if complete else "fail",
                          f"{len(records)} records at positions 0..{len(records) - 1}, chain says "
                          f"{onchain.record_count}" if complete else
                          f"index has {len(records)} records, chain says {onchain.record_count}, "
                          "or positions have gaps"))
    if not complete:
        causes.append("RECORD_SET_INCOMPLETE")

    leaves = [_hex_bytes(r.leaf_hash) for r in records]
    if records and all(leaves):
        recomputed = MerkleTree(leaves).root.hex()  # type: ignore[arg-type]
        rc_ok = recomputed == onchain.merkle_root
        v.checks.append(Check("recomputed_root_equals_chain_root", "pass" if rc_ok else "fail",
                              "root recomputed from the indexed leaves equals the on-chain root" if rc_ok
                              else f"recomputed {recomputed[:16]}... vs on-chain {onchain.merkle_root[:16]}..."))
        if not rc_ok:
            causes.append("LEDGER_INDEX_MODIFIED")
    else:
        v.checks.append(Check("recomputed_root_equals_chain_root", "fail",
                              "no usable leaves in the index for this batch"))
        causes.append("LEDGER_INDEX_MODIFIED")

    findings = [classify_record(r, chain_root, (sources or {}).get(r.id, SourceResult(False)))
                for r in records]
    bad_index = [f.record_id for f in findings if not f.index_ok]
    v.checks.append(Check("every_record_included_in_onchain_root", "fail" if bad_index else "pass",
                          f"{len(bad_index)} record(s) fail their stored leaf/proof against the chain"
                          if bad_index else f"all {len(records)} stored leaves + proofs reproduce the on-chain root"))
    if bad_index:
        causes.append("LEDGER_INDEX_MODIFIED")
        v.index_culprits = bad_index
    if supplied:
        bad_src = [f.record_id for f in findings if f.index_ok and f.source in ("modified", "missing")]
        v.checks.append(Check("source_full_record_set", "fail" if bad_src else "pass",
                              f"{len(bad_src)} record(s) recomputed from source no longer match the anchor"
                              if bad_src else "every record recomputed from source is included in the on-chain root"))
        if bad_src:
            causes.append("SOURCE_DATA_MODIFIED")
            v.source_culprits = bad_src
    else:
        v.checks.append(Check("source_full_record_set", "skipped", "full record set not supplied"))
    v.causes = list(dict.fromkeys(causes))
    return _finish(v, None if supplied else
                   "that the source data still matches (full record set not supplied).")


class Verifier:
    def __init__(self, index: Index, chain: ChainClient, cfg: Config):
        self.index, self.chain, self.cfg = index, chain, cfg

    def _chain_batch(self, batch: BatchRow) -> tuple[Optional[OnChainBatch], str]:
        try:
            return self.chain.get_batch(batch.chain_batch_id), ""
        except ChainError as exc:
            return None, str(exc)

    def _source_for(self, rec: RecordRow, override: Optional[Source], use_source: bool,
                    cache: dict) -> SourceResult:
        if not use_source:
            return SourceResult(False, note="source check disabled")
        try:
            if override is not None:
                src = override
            else:
                if rec.locator not in cache:
                    cache[rec.locator] = build_source(rec.locator, self.cfg.aegis_db_url)
                src = cache[rec.locator]
            return SourceResult(True, src.lookup(rec))
        except SourceUnavailable as exc:
            return SourceResult(False, note=f"source unavailable: {exc}")

    def verify_record(self, record_id: int, source: Optional[Source] = None,
                      use_source: bool = True) -> Verdict:
        rec = self.index.get_record(record_id)
        if rec is None:
            raise LookupError(f"record {record_id} not found")
        batch = self.index.get_batch(rec.batch_id) if rec.batch_id else None
        if rec.status != "anchored" or batch is None:
            return _finish(Verdict(scope=f"record {rec.id}", status=INCONCLUSIVE,
                                   checks=[Check("chain_lookup", "skipped",
                                                 "record is still pending: not anchored yet")]),
                           "anything: the record has not been anchored.")
        onchain, err = self._chain_batch(batch)
        src = self._source_for(rec, source, use_source, {})
        return evaluate_record(rec, batch, onchain, err, src)

    def verify_batch(self, batch_id: int, source: Optional[Source] = None,
                     use_source: bool = False) -> Verdict:
        """Check a batch against the chain. With ``use_source`` (or an explicit ``source``)
        every record is also re-fetched from source data ("full record set supplied")."""
        batch = self.index.get_batch(batch_id)
        if batch is None:
            raise LookupError(f"batch {batch_id} not found")
        records = self.index.batch_records(batch_id)
        onchain, err = self._chain_batch(batch)
        sources = None
        if source is not None or use_source:
            cache: dict = {}
            sources = {r.id: self._source_for(r, source, True, cache) for r in records}
            if any(not s.checked for s in sources.values()):
                note = next(s.note for s in sources.values() if not s.checked)
                v = evaluate_batch(batch, records, onchain, err, None)
                v.not_proven.append(f"full-record-set check was requested but skipped: {note}")
                return v
        return evaluate_batch(batch, records, onchain, err, sources)
