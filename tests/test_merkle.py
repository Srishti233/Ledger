import hashlib

import pytest

from ledger.merkle import (
    MerkleError, MerkleTree, ProofStep, compute_root, leaf_hash, node_hash,
    proof_from_json, proof_to_json, root_from_proof, verify_inclusion,
)


def h(a: bytes, b: bytes) -> bytes:
    """Independent reference for an internal node: sorted pair, 0x01 prefix."""
    lo, hi = sorted((a, b))
    return hashlib.sha256(b"\x01" + lo + hi).digest()


def leaves(n):
    return [leaf_hash(bytes([i])) for i in range(n)]


def test_leaf_and_node_hash_are_domain_separated():
    data = b"x" * 64
    assert leaf_hash(data) == hashlib.sha256(b"\x00" + data).digest()
    a, b = leaves(2)
    assert node_hash(a, b) == hashlib.sha256(b"\x01" + min(a, b) + max(a, b)).digest()
    assert node_hash(a, b) == node_hash(b, a)


def test_single_leaf_root_is_leaf_and_proof_empty():
    (a,) = leaves(1)
    t = MerkleTree([a])
    assert t.root == a and t.proof(0) == [] and verify_inclusion(a, [], a)


def test_two_leaves():
    a, b = leaves(2)
    assert compute_root([a, b]) == h(a, b)


def test_three_leaves_hand_computed():
    a, b, c = leaves(3)
    assert compute_root([a, b, c]) == h(h(a, b), c)  # odd node promoted, not duplicated


def test_four_leaves_hand_computed():
    a, b, c, d = leaves(4)
    assert compute_root([a, b, c, d]) == h(h(a, b), h(c, d))


def test_five_leaves_hand_computed():
    a, b, c, d, e = leaves(5)
    assert compute_root([a, b, c, d, e]) == h(h(h(a, b), h(c, d)), e)


def test_seven_leaves_hand_computed():
    a, b, c, d, e, f, g = leaves(7)
    assert compute_root([a, b, c, d, e, f, g]) == h(h(h(a, b), h(c, d)), h(h(e, f), g))


def test_odd_leaf_is_not_duplicated():
    a, b, c = leaves(3)
    assert compute_root([a, b, c]) != compute_root([a, b, c, c])


def test_every_leaf_proves_for_many_sizes():
    for n in list(range(1, 20)) + [31, 32, 33, 100]:
        ls = leaves(n)
        t = MerkleTree(ls)
        for i, leaf in enumerate(ls):
            assert verify_inclusion(leaf, t.proof(i), t.root), (n, i)


def test_proof_length_is_logarithmic():
    t = MerkleTree(leaves(8))
    assert all(len(t.proof(i)) == 3 for i in range(8))


def test_wrong_leaf_wrong_root_and_tampered_proof_fail():
    ls = leaves(7)
    t = MerkleTree(ls)
    proof = t.proof(2)
    assert not verify_inclusion(leaf_hash(b"other"), proof, t.root)
    assert not verify_inclusion(ls[2], proof, leaf_hash(b"not the root"))
    bad = [ProofStep(leaf_hash(b"zzz"), proof[0].position)] + proof[1:]
    assert not verify_inclusion(ls[2], bad, t.root)
    assert not verify_inclusion(ls[2], proof[:-1], t.root)


def test_proof_from_another_leaf_does_not_verify():
    ls = leaves(8)
    t = MerkleTree(ls)
    assert not verify_inclusion(ls[0], t.proof(5), t.root)


def test_verification_ignores_position_labels():
    ls = leaves(5)
    t = MerkleTree(ls)
    flipped = [ProofStep(s.sibling, "left" if s.position == "right" else "right") for s in t.proof(1)]
    assert verify_inclusion(ls[1], flipped, t.root)


def test_internal_node_cannot_pass_as_leaf_data():
    # Classic second-preimage attack: present the concatenation of two child hashes as
    # leaf *data*. Domain separation makes its leaf hash differ from the node hash.
    a, b, c, d = leaves(4)
    t = MerkleTree([a, b, c, d])
    forged_leaf = leaf_hash(a + b)
    assert forged_leaf != h(a, b)
    assert not verify_inclusion(forged_leaf, [ProofStep(h(c, d), "right")], t.root)


def test_empty_batch_and_bad_leaves_rejected():
    with pytest.raises(MerkleError):
        MerkleTree([])
    with pytest.raises(MerkleError):
        MerkleTree([b"short"])
    with pytest.raises(MerkleError):
        MerkleTree(leaves(3)).proof(3)
    with pytest.raises(MerkleError):
        MerkleTree(leaves(3)).proof(-1)


def test_verify_rejects_wrong_lengths():
    assert not verify_inclusion(b"short", [], b"x" * 32)
    assert not verify_inclusion(b"x" * 32, [], b"short")


def test_construction_is_deterministic():
    ls = leaves(6)
    assert MerkleTree(ls).root == MerkleTree(list(ls)).root


def test_root_commits_to_leaf_set_not_to_sibling_order():
    # Documented consequence of sorted-pair hashing: swapping two *sibling* leaves does not
    # change the root, but changing, adding or removing any leaf does.
    a, b, c, d = leaves(4)
    assert compute_root([a, b, c, d]) == compute_root([b, a, d, c])
    assert compute_root([a, b, c, d]) != compute_root([a, b, c])
    assert compute_root([a, b, c, d]) != compute_root([a, b, c, leaf_hash(b"changed")])


def test_json_roundtrip():
    t = MerkleTree(leaves(6))
    proof = t.proof(4)
    again = proof_from_json(proof_to_json(proof))
    assert again == proof
    assert root_from_proof(leaves(6)[4], again) == t.root
    with pytest.raises(MerkleError):
        proof_from_json([{"sibling": "abcd", "position": "left"}])
