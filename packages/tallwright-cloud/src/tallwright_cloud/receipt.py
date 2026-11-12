# SPDX-License-Identifier: Apache-2.0
"""The recording door's receipt, read exactly as the door writes it, or not at all.

``tallwright-receipt/1`` says, per line sent: which record,
whether it was recorded now or recognised as already held, at which leaf of a log of which size,
under which record hash, chained to which one, at what time and who set that time — and a note that
it is a confirmation, not a proof. That note is the door's and this client adds nothing to it: a
receipt is unsigned, no witness has seen the record until an anchor covers its leaf, and the proof is
the exhibit made afterwards.

**Read strictly.** A field missing, of the wrong type, or naming another record is not a smaller
receipt; it is no receipt, and the record stays pending. A field the door adds later is kept in
:attr:`Receipt.as_written` and read past: a later version saying more does not change what this one
says.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tallwright_core.hashing import is_content_address

RECEIPT_SCHEMA = "tallwright-receipt/1"
_STATUSES = frozenset({"recorded", "already_held"})
_TIME_SOURCES = frozenset({"sender", "archive", "unknown"})


class UnreadableReceipt(ValueError):
    """What came back is not the door's receipt for this record."""


def _count(answer: dict[str, Any], key: str) -> int:
    value = answer.get(key)
    # `bool` is an `int` in Python and never a count in a receipt.
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise UnreadableReceipt(f"{key} is {value!r}, not a count")
    return value


def _text(answer: dict[str, Any], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str) or not value:
        raise UnreadableReceipt(f"{key} is {value!r}, not a sentence")
    return value


@dataclass(frozen=True)
class Receipt:
    """Where the door says this record is, and who set its time. A confirmation, not a proof."""

    record_id: str
    #: ``recorded`` now, or ``already_held``: an earlier send of the same line was recorded.
    status: str
    #: The record's position in the log, from 0. An exhibit of it names the same leaf.
    leaf_index: int
    #: The content address of the record the door built around this line.
    record_hash: str
    #: The record it is chained to, or None for the first record of a log.
    prev_record_hash: str | None
    timestamp: str
    #: ``sender`` (this line stated it), ``archive`` (the door stamped it) or ``unknown``.
    timestamp_source: str
    #: How many records the log held when this receipt was written.
    log_size: int
    #: The door's own sentence about what a receipt is.
    note: str
    #: The receipt as the door wrote it, fields this client does not read included.
    as_written: dict[str, Any]

    @classmethod
    def read(cls, answer: object, record_id: str) -> Receipt:
        """The door's receipt for ``record_id``, or :class:`UnreadableReceipt` saying what is wrong."""
        if not isinstance(answer, dict):
            raise UnreadableReceipt(f"a receipt is a JSON object, not {type(answer).__name__}")
        if answer.get("schema") != RECEIPT_SCHEMA:
            raise UnreadableReceipt(f"schema is {answer.get('schema')!r}, not {RECEIPT_SCHEMA!r}")
        if answer.get("record_id") != record_id:
            raise UnreadableReceipt(
                f"record_id is {answer.get('record_id')!r}: a receipt for another record is no "
                f"receipt for {record_id!r}"
            )
        status = answer.get("status")
        if status not in _STATUSES:
            raise UnreadableReceipt(f"status is {status!r}, not one of {sorted(_STATUSES)}")
        leaf, size = _count(answer, "leaf_index"), _count(answer, "log_size")
        if size <= leaf:
            raise UnreadableReceipt(f"log_size {size} does not hold leaf_index {leaf}")
        record_hash = answer.get("record_hash")
        if not isinstance(record_hash, str) or not is_content_address(record_hash):
            raise UnreadableReceipt(f"record_hash {record_hash!r} is not a content address")
        prev = answer.get("prev_record_hash")
        if leaf == 0 and prev is not None:
            raise UnreadableReceipt("prev_record_hash names a record before the first one")
        if leaf > 0 and (not isinstance(prev, str) or not is_content_address(prev)):
            raise UnreadableReceipt(f"prev_record_hash {prev!r} is not the address of the record before")
        source = answer.get("timestamp_source")
        if source not in _TIME_SOURCES:
            raise UnreadableReceipt(f"timestamp_source is {source!r}, not one of {sorted(_TIME_SOURCES)}")
        return cls(
            record_id=record_id,
            status=str(status),
            leaf_index=leaf,
            record_hash=record_hash,
            prev_record_hash=prev,
            timestamp=_text(answer, "timestamp"),
            timestamp_source=str(source),
            log_size=size,
            note=_text(answer, "note"),
            as_written=dict(answer),
        )
