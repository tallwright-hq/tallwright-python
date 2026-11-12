# SPDX-License-Identifier: Apache-2.0
"""tallwright_core — shared record schema, content-addressing, and Merkle primitives.

The dependency-light foundation every other Tallwright package builds on. No
networked or external-service code lives here (no TSA, transparency log, or storage).
"""

from __future__ import annotations

from .document import AmbiguousDocument, DocumentTooDeep, load_document
from .write import write_document
from .canonical import (
    MAX_CANONICAL_DEPTH,
    MAX_CANONICAL_NODES,
    CanonicalizationError,
    canonicalize,
)
from .hashing import (
    content_address,
    decode_content_address,
    decode_multihash,
    multihash,
    MalformedSalt,
    SALT_LEN,
    address_from_digest,
    opens_address,
    sha256,
    verify,
)
from .merkle import (
    MerkleTree,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from .schema import (
    CANONICALIZATION_METHOD,
    HASH_ALGORITHM,
    SCHEMA_VERSION,
    AnchorReceipt,
    EventType,
    GapManifest,
    Record,
    link,
    verify_chain,
)

__all__ = [
    # reading a document, and replacing one
    "load_document",
    "AmbiguousDocument",
    "DocumentTooDeep",
    "write_document",
    # canonicalization
    "canonicalize",
    "CanonicalizationError",
    "MAX_CANONICAL_DEPTH",
    "MAX_CANONICAL_NODES",
    # hashing
    "sha256",
    "multihash",
    "decode_multihash",
    "content_address",
    "MalformedSalt",
    "SALT_LEN",
    "address_from_digest",
    "opens_address",
    "decode_content_address",
    "verify",
    # merkle
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "inclusion_proof",
    "consistency_proof",
    "verify_inclusion",
    "verify_consistency",
    "MerkleTree",
    # schema
    "EventType",
    "GapManifest",
    "AnchorReceipt",
    "Record",
    "link",
    "verify_chain",
    "SCHEMA_VERSION",
    "HASH_ALGORITHM",
    "CANONICALIZATION_METHOD",
]
