# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 Merkle tree: root, inclusion proofs, consistency proofs, verifiers.

Hashing is domain-separated exactly per RFC 6962 (leaf = ``SHA-256(0x00 || entry)``,
interior = ``SHA-256(0x01 || left || right)``) so proofs are portable and
interoperable with Certificate Transparency / Trillian-Tessera tooling — which is
what makes an export verifiable years later with no live service.

The prover (:func:`inclusion_proof`, :func:`consistency_proof`) follows the
recursive RFC 6962 definitions; the verifiers follow the iterative RFC 9162
algorithms. They are deliberately separate code paths so their agreement is
strong evidence of correctness.
"""

from __future__ import annotations

from .hashing import sha256

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(entry: bytes) -> bytes:
    """RFC 6962 leaf hash of a raw entry."""
    return sha256(LEAF_PREFIX + entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash of two child hashes."""
    return sha256(NODE_PREFIX + left + right)


def _largest_power_of_two_less_than(n: int) -> int:
    # Largest k that is a power of two with k < n (requires n >= 2).
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_root(entries: list[bytes]) -> bytes:
    """Return the RFC 6962 Merkle Tree Hash (MTH) over the ordered entries.

    The hash of an empty list is the hash of the empty string.
    """
    if not entries:
        return sha256(b"")
    if len(entries) == 1:
        return leaf_hash(entries[0])
    k = _largest_power_of_two_less_than(len(entries))
    return node_hash(merkle_root(entries[:k]), merkle_root(entries[k:]))


def inclusion_proof(entries: list[bytes], index: int) -> list[bytes]:
    """Return the audit PATH for the entry at ``index`` (RFC 6962)."""
    n = len(entries)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if index < k:
        return inclusion_proof(entries[:k], index) + [merkle_root(entries[k:])]
    return inclusion_proof(entries[k:], index - k) + [merkle_root(entries[:k])]


def _subproof(m: int, entries: list[bytes], at_root: bool) -> list[bytes]:
    n = len(entries)
    if m == n:
        return [] if at_root else [merkle_root(entries)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(m, entries[:k], at_root) + [merkle_root(entries[k:])]
    return _subproof(m - k, entries[k:], False) + [merkle_root(entries[:k])]


def consistency_proof(entries: list[bytes], first_size: int) -> list[bytes]:
    """Return the consistency PROOF between the tree of ``first_size`` and the full tree."""
    n = len(entries)
    if not 0 <= first_size <= n:
        raise ValueError("first_size out of range")
    if first_size == 0 or first_size == n:
        return []
    return _subproof(first_size, entries, True)


def verify_inclusion(
    entry: bytes, index: int, tree_size: int, root: bytes, proof: list[bytes]
) -> bool:
    """Verify an inclusion proof for a raw ``entry`` (RFC 9162 algorithm)."""
    # BOTH bounds, and a positive tree_size. A NEGATIVE index must be rejected: Python's saturating
    # >> and & on negatives pin `fn` to a fixed parity, so every leaf would otherwise have an infinite
    # family of negative aliases that verify against the same signed root — a forged, producer-
    # controlled leaf_index reading as VALID. (The prover, inclusion_proof, always checked both
    # bounds; only the verifier did not. Found in review.)
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(entry)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: list[bytes],
) -> bool:
    """Verify a consistency proof between two tree sizes (RFC 9162 algorithm)."""
    # Reject negative sizes for the same reason as verify_inclusion: a negative operand would drive
    # the shift/parity loop below into meaningless state rather than failing closed.
    if first_size < 0 or second_size < 0 or first_size > second_size:
        return False
    if first_size == second_size:
        return len(proof) == 0 and first_root == second_root
    if first_size == 0:
        return len(proof) == 0
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    it = iter(proof)
    if fn == 0:
        fr = sr = first_root
    else:
        try:
            fr = sr = next(it)
        except StopIteration:
            return False
    for c in it:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


class MerkleTree:
    """A small append-only RFC 6962 tree over in-memory entries."""

    def __init__(self, entries: list[bytes] | None = None) -> None:
        self._entries: list[bytes] = list(entries) if entries else []

    def add(self, entry: bytes) -> int:
        """Append a raw entry; return the new tree size."""
        self._entries.append(entry)
        return len(self._entries)

    @property
    def size(self) -> int:
        return len(self._entries)

    def entry(self, index: int) -> bytes:
        return self._entries[index]

    def root(self) -> bytes:
        return merkle_root(self._entries)

    def inclusion_proof(self, index: int) -> list[bytes]:
        return inclusion_proof(self._entries, index)

    def consistency_proof(self, first_size: int) -> list[bytes]:
        return consistency_proof(self._entries, first_size)
