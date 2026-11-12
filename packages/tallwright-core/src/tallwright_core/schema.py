# SPDX-License-Identifier: Apache-2.0
"""The court-defensible record envelope, canonicalization, and hash-chain.

Realizes the 14-field record schema. Design rule:
the *record* holds hashes + metadata; the full payload (the context value, or the
action parameters) is sealed **off-record** and referenced by ``payload_hash``.

Canonicalization is RFC 8785 (JCS) so the record hash is reproducible by a court
expert years later. ``anchor_receipt`` and ``certification_pointer`` are attached
*after* sealing (anchoring is batched; certification is added later), so they are
EXCLUDED from the hashed and hash-chained content — otherwise a record could not
be anchored after its hash was computed.

Framing discipline (non-negotiable): we record the context received and the action
triggered — never the agent's reasoning or intent. Integrity is from the moment of
capture, not the truth of the inputs.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonicalize
from .hashing import content_address, multihash

SCHEMA_VERSION = "0.1.0"
HASH_ALGORITHM = "sha2-256"
CANONICALIZATION_METHOD = "RFC8785-JCS"

# Attached post-sealing -> never part of the record hash / chain.
_UNHASHED_FIELDS = ("anchor_receipt", "certification_pointer")


class EventType(str, Enum):
    """We seal what the agent received and what it triggered — nothing else."""

    CONTEXT_RECEIVED = "CONTEXT_RECEIVED"
    ACTION_TRIGGERED = "ACTION_TRIGGERED"


#: How a capture gap announces itself in ``GapManifest.notes``.
#:
#: Defined HERE because two packages have to agree on it and neither owns the other: the capture
#: middleware writes it when a capture is dropped, and the alarm reads it to tell the operator.
#: Two spellings of one marker is a gap that is recorded and never reported — which is the same as
#: not recording it, on the day it matters.
RUPTURE_NOTE_PREFIX = "rupture: "


class GapManifest(BaseModel):
    """Declares which capture tiers were active, scoping any completeness claim.

    Every tier defaults to FALSE, including the strongest one. A record built without saying how it
    was captured must not claim we watched it happen — and until 2026-08-25 it did, because
    ``tier1_runtime_hooks`` defaulted to True and ``Record.gap_manifest`` has a default factory.
    Both archive paths of the product's closed service build records without a manifest, so every
    archived record asserted boundary capture; on the hashes-only path, where the operator sends an
    address and we see nothing by construction, that assertion was flatly false.

    The adapter that genuinely installs runtime hooks says so explicitly and still does. Everything
    else now under-claims, which is the only direction this may ever fail in.
    """

    model_config = ConfigDict(extra="forbid")

    tier1_runtime_hooks: bool = False
    tier2_transport_bytes: bool = False
    tier3_mcp_proxy: bool = False
    notes: str | None = None


class AnchorReceipt(BaseModel):
    """External-anchor evidence (the moat field); attached after batched anchoring."""

    model_config = ConfigDict(extra="forbid")

    merkle_root: str
    tree_size: int
    anchored_at: str
    timestamp_ref: str | None = None  # always set; honest about the token
    timestamp_algorithm: str | None = None  # e.g. "local-ed25519-ts" (non-qualified) vs "rfc3161-cms"
    qualified_timestamp_ref: str | None = None  # ONLY set for a genuinely qualified token
    witness_checkpoint_ref: str | None = None
    public_anchor_ref: str | None = None


class Record(BaseModel):
    """A single sealed context/action record.

    The field numbers in comments number the record's fourteen fields.
    """

    model_config = ConfigDict(extra="forbid")

    # 13 — re-verifiability + reproducible hashing
    schema_version: str = SCHEMA_VERSION
    hash_algorithm: str = HASH_ALGORITHM
    canonicalization_method: str = CANONICALIZATION_METHOD

    # 1 record id, 2 chain link, 3 content-address of the sealed payload
    record_id: str
    prev_record_hash: str | None = None
    payload_hash: str

    # 4 trusted time (RFC 3339 string; upgrade to a qualified TS where weight matters)
    timestamp: str

    # 5 runtime + version, 6 accountable operator
    agent_system_id: str
    agent_version: str
    deployer_operator_id: str

    # 7 event type; 8/9 the payload itself is off-record (payload_hash), action_type
    #   is the small inline metadata for ACTION_TRIGGERED
    event_type: EventType
    action_type: str | None = None

    # 10 accountable authority
    actor_authority: str | None = None

    # 11 retention + legal hold
    retention_class: str
    legal_hold: bool = False

    # capture-completeness scope
    gap_manifest: GapManifest = Field(default_factory=GapManifest)

    # 12 anchor (post-seal) + 14 certification (post-seal) -> EXCLUDED from the hash
    anchor_receipt: AnchorReceipt | None = None
    certification_pointer: str | None = None

    @model_validator(mode="after")
    def _check_event_fields(self) -> Record:
        if self.event_type is EventType.ACTION_TRIGGERED:
            if not self.action_type:
                raise ValueError("ACTION_TRIGGERED requires action_type")
        elif self.action_type is not None:
            raise ValueError("action_type must be unset for CONTEXT_RECEIVED")
        return self

    def hashable_dict(self) -> dict[str, Any]:
        """The JSON-able record content that the hash/chain cover (post-seal fields removed)."""
        data: dict[str, Any] = self.model_dump(mode="json")
        for field in _UNHASHED_FIELDS:
            data.pop(field, None)
        return data

    def canonical_bytes(self) -> bytes:
        """Deterministic RFC 8785 (JCS) serialization of the hashable content."""
        return canonicalize(self.hashable_dict())

    def record_hash(self) -> bytes:
        """The raw multihash over the canonical bytes."""
        return multihash(self.canonical_bytes())

    def record_hash_address(self) -> str:
        """The content address (multibase string) of this record's hash."""
        return content_address(self.canonical_bytes())


def link(prev: Record, **fields: Any) -> Record:
    """Build the next record, chaining ``prev_record_hash`` to ``prev``."""
    return Record(prev_record_hash=prev.record_hash_address(), **fields)


def verify_chain(records: list[Record]) -> bool:
    """Return True iff each record's ``prev_record_hash`` matches the prior record."""
    prev_addr: str | None = None
    for rec in records:
        if rec.prev_record_hash != prev_addr:
            return False
        prev_addr = rec.record_hash_address()
    return True
