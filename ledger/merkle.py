"""SHA-256 Merkle tree with domain separation and sorted-pair hashing.

Design (documented because the non-obvious parts are where bugs hide):

* Leaves and internal nodes are hashed with different one-byte prefixes
  (0x00 for leaves, 0x01 for nodes). Without this, an internal node could be
  presented as a leaf (the classic second-preimage attack on Merkle trees).
* Internal nodes hash the *sorted* pair of children, so a proof does not need to
  carry left/right directions to be verified. ``ProofStep.position`` is kept as
  informational metadata only and is never used by ``verify_inclusion``.
  Consequence: a proof shows a leaf is *in* the tree, not *where* it is.
* An odd node at the end of a level is promoted unchanged to the next level.
  It is NOT duplicated (duplicating the last node, as Bitcoin does, lets two
  different leaf lists share a root). A promoted node contributes no proof step.
* A single-leaf tree has root == leaf hash and an empty proof.
* An empty tree is an error: there is nothing to anchor.

Everything here is pure computation: no network, no chain, no database.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterable, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
HASH_LEN = 32


class MerkleError(ValueError):
    """Raised for malformed Merkle input."""


def leaf_hash(data: bytes) -> bytes:
    """Hash raw leaf data with the leaf domain-separation prefix."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(a: bytes, b: bytes) -> bytes:
    """Hash two child hashes (order-independent) with the node prefix."""
    lo, hi = (a, b) if a <= b else (b, a)
    return hashlib.sha256(NODE_PREFIX + lo + hi).digest()


@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    position: str  # "left" or "right": where the sibling sat. Informational only.

    def to_json(self) -> dict:
        return {"sibling": self.sibling.hex(), "position": self.position}

    @staticmethod
    def from_json(obj: dict) -> "ProofStep":
        sibling = bytes.fromhex(obj["sibling"])
        if len(sibling) != HASH_LEN:
            raise MerkleError("proof sibling must be 32 bytes")
        return ProofStep(sibling=sibling, position=str(obj.get("position", "")))


def _check_leaves(leaves: Sequence[bytes]) -> None:
    if len(leaves) == 0:
        raise MerkleError("cannot build a Merkle tree from zero leaves")
    for leaf in leaves:
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != HASH_LEN:
            raise MerkleError("every leaf must be a 32-byte hash")


def _next_level(level: list[bytes]) -> list[bytes]:
    out = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2 == 1:
        out.append(level[-1])  # promote the odd node unchanged
    return out


class MerkleTree:
    """Merkle tree over a list of 32-byte leaf hashes (see ``leaf_hash``)."""

    def __init__(self, leaf_hashes: Sequence[bytes]):
        _check_leaves(leaf_hashes)
        level = [bytes(x) for x in leaf_hashes]
        self.levels: list[list[bytes]] = [level]
        while len(level) > 1:
            level = _next_level(level)
            self.levels.append(level)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def __len__(self) -> int:
        return len(self.levels[0])

    def proof(self, index: int) -> list[ProofStep]:
        if not 0 <= index < len(self):
            raise MerkleError(f"leaf index {index} out of range 0..{len(self) - 1}")
        steps: list[ProofStep] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    steps.append(ProofStep(level[idx + 1], "right"))
                # else: odd node promoted, no sibling at this level
            else:
                steps.append(ProofStep(level[idx - 1], "left"))
            idx //= 2
        return steps


def compute_root(leaf_hashes: Sequence[bytes]) -> bytes:
    return MerkleTree(leaf_hashes).root


def root_from_proof(leaf: bytes, proof: Iterable[ProofStep]) -> bytes:
    acc = bytes(leaf)
    for step in proof:
        acc = node_hash(acc, step.sibling)
    return acc


def verify_inclusion(leaf: bytes, proof: Iterable[ProofStep], root: bytes) -> bool:
    """True iff ``leaf`` is in the tree with this ``root``. Pure hash computation."""
    if len(leaf) != HASH_LEN or len(root) != HASH_LEN:
        return False
    return hmac.compare_digest(root_from_proof(leaf, proof), bytes(root))


def proof_to_json(proof: Iterable[ProofStep]) -> list[dict]:
    return [s.to_json() for s in proof]


def proof_from_json(items: Iterable[dict]) -> list[ProofStep]:
    return [ProofStep.from_json(i) for i in items]
