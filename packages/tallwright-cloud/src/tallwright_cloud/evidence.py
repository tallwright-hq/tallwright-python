# SPDX-License-Identifier: Apache-2.0
"""The caller's evidence: the pair is safe before the door hears of the record.

One folder per record, named by its ``record_id``, in an :class:`~tallwright_cloud.store.EvidenceStore`
(a directory, or a bucket)::

    disclosure.json   {"salt", "payload_b64"}: what `evidence-verify --disclosure` reads (spec §6)
    line.json         the exact bytes sent to the door
    receipt.json      the door's receipt, once it gave one
    refused.json      {"status", "said"}, when the door refused the line
    lost.json         when a later receipt showed the door's log no longer holds what receipt.json names
    receipt-2.json    the door's receipt for the record sent again after that, and so on
    exhibit/          evidence.json, policy.json, our-claims.json: the exhibit, once it was taken

and beside the folders one marker per record still to be sent, ``.outbox/<record_id>``, and one note
per record hash a kept receipt names as its predecessor, ``.chain/<record_hash>``, naming the record
that follows it (:meth:`Evidence.taken_back_by`).

**Write-ahead.** The disclosure, the outbox marker and the line are written, each durable before the
next, BEFORE anything is sent. A process that dies after sending and before the answer loses nothing:
the record is pending, and its line is sent again as it was. Written the other way round, a record
could reach the door whose salt existed only in the memory of a process that is gone, and a record
whose salt is gone can never be opened again, by anyone. A pending line is sent again only while its
disclosure still opens its address, so nothing is recorded that nobody could open.

**States, read off the folder.** ``line.json`` without ``receipt.json`` or ``refused.json`` is pending.
A folder with only a disclosure was never sent, and neither was one whose marker came without a line.
Nothing is ever overwritten: a ``record_id`` already here is refused before anything is sent, so a
second capture under the same name cannot replace the salt of the first, and the refusal says what
became of the record it names. The marker exists so that what is still to be sent is found without
reading every record ever kept; it is removed once the door confirmed or refused the line, and a
marker left behind by a process that died in between is recognised and removed by the next one to
look.

**A store's failure is not always the write's.** An answer lost after the bytes landed, or a folder
that could not be flushed after the name was made, is reported as a failure of a write that is
there. So a line the store reports as not written is looked for: there as written, the record is
pending like any other; not there, its marker is withdrawn, so that a write that lands after all is
not sent behind the back of a caller who was told nothing was.

**A receipt can be taken back, and is not overwritten either.** A door whose log was put back to a
state after its last anchor no longer holds what it receipted since, and nothing on its side can tell.
This evidence can: the next receipt puts another record after the same record. Then ``lost.json``
says which receipt took ``receipt.json`` back, the record is pending again with its marker, and the
receipt of the record sent anew is ``receipt-2.json``. The receipt that stands is the newest one no
``lost`` note names.

**A marker names the key it was written under.** Not the key: a fingerprint of it, which says nothing
about the key itself. Two Environments whose evidence was pointed at one directory by mistake each
send only their own pending records again, never the other's under the wrong key into the wrong
log. A record pending under a key that was since replaced is sent again under the new one only when
the caller says so (``adopt``): whether the new key belongs to the same Environment is the caller's
to know, not this directory's.

**The pair is never a local variable of a frame an error can leave through.** It travels as the
:class:`Commitment`, whose repr shows the address and nothing else, and its bytes exist only inside
the expression that writes them. The store's own error passed through the frames that wrote them,
so every error here is raised after its handler and chains to nothing. An error tracker that records
the local variables of every frame of a traceback records no salt and no content from this package.

**This is the customer's copy of their own content.** It is the only place the plaintext exists for
Cloud Proof, and it is what makes a record openable at all. Where it lives, how it is backed up and
when it is deleted are the owner's to decide, and deleting a disclosure ends the possibility of ever
opening that record.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from tallwright_core.hashing import is_content_address, opens_address

from .commit import Commitment
from .errors import EvidenceError
from .ids import checked_record_id
from .store import EvidenceStore

DISCLOSURE = "disclosure.json"
LINE = "line.json"
RECEIPT = "receipt.json"
REFUSED = "refused.json"
LOST = "lost.json"
EXHIBIT = "exhibit"
#: Where the markers of records still to be sent are. A record id starts with a letter or a digit, so
#: no record's folder can take this name.
OUTBOX = ".outbox"
#: Which record this evidence holds a receipt for right after each record hash: how a receipt that
#: puts another record there is found without reading every receipt ever kept.
CHAIN = ".chain"


def _receipt(taken: int) -> str:
    """The name of a record's receipt after ``taken`` earlier ones were taken back: nearly always 0."""
    return RECEIPT if taken == 0 else f"receipt-{taken + 1}.json"


def _lost(taken: int) -> str:
    """The name of the note that the record's receipt number ``taken`` was taken back."""
    return LOST if taken == 0 else f"lost-{taken + 1}.json"


def _json(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _document(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    try:
        document = json.loads(data)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def _opens(disclosure: bytes | None, address: str) -> bool:
    """Whether the disclosure opens ``address``. Every failure is a False that stays in here."""
    try:
        said = json.loads(disclosure or b"")
        return opens_address(
            address,
            base64.b64decode(said["salt"], validate=True),
            base64.b64decode(said["payload_b64"], validate=True),
        )
    except (ValueError, KeyError, TypeError):
        return False


def _failure(failed: OSError) -> str:
    return str(failed.strerror or failed)


class Evidence:
    """One Environment's evidence, in one store."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def name(self, record_id: str, part: str = "") -> str:
        name = checked_record_id(record_id)
        return f"{name}/{part}" if part else name

    def locate(self, record_id: str, part: str = "") -> str:
        return self.store.locate(self.name(record_id, part))

    def begin(self, record_id: str, committed: Commitment, line: bytes, binding: str) -> str:
        """Where the record's evidence is, with its pair, its marker and its line safe. Nothing is sent yet."""
        taken, unwritten = False, None
        try:
            self.store.create(self.name(record_id, DISCLOSURE), _json(committed.disclosure()))
        except FileExistsError:
            taken = True
        except OSError as failed:
            unwritten = _failure(failed)
        if taken:
            raise EvidenceError(self._kept_already(record_id), record_id=record_id)
        if unwritten is not None:
            raise EvidenceError(
                f"{record_id}: its pair could not be written ({unwritten}). Nothing was sent: a record "
                "whose salt is not kept is a record nobody could ever open",
                record_id=record_id,
            )
        try:
            self.store.create(f"{OUTBOX}/{checked_record_id(record_id)}", _json({"key": binding}))
            self.store.create(self.name(record_id, LINE), line)
        except OSError as failed:
            unwritten = _failure(failed)
        if unwritten is not None and not self._holds(record_id, line):
            raise EvidenceError(self._withdrawn(record_id, unwritten), record_id=record_id)
        return self.locate(record_id)

    def _kept_already(self, record_id: str) -> str:
        """Why a record_id already kept is refused, by what became of the record it names. The next step
        differs: a capture under another record_id is right only where the door never held it."""
        already = f"{record_id}: this record_id is already in the evidence, and its pair is never replaced."
        try:
            receipt = self.store.read(self.name(record_id, RECEIPT))
            refused = None if receipt is not None else self.store.read(self.name(record_id, REFUSED))
            sent = None if receipt is not None or refused is not None else self.store.read(self.name(record_id, LINE))
        except OSError as failed:
            return (
                f"{already} Nothing was sent, and what became of the record kept under it could not be "
                f"read ({_failure(failed)}): look at {self.locate(record_id)} first, since a pending one is "
                f"sent by resend({record_id!r}) and a capture under another record_id would record it twice"
            )
        if receipt is not None:
            return (
                f"{already} The door confirmed the record kept under it (its receipt: "
                f"{self.locate(record_id, RECEIPT)}). Nothing was sent: if that is this event, it is "
                "recorded already, and a capture under another record_id would record it twice"
            )
        if refused is not None:
            return (
                f"{already} The door refused the record kept under it ({self.locate(record_id, REFUSED)}). "
                "Nothing was sent; capture this event under a record_id of its own"
            )
        if sent is not None:
            return (
                f"{already} The record kept under it is pending: its line was written to be sent, and the "
                f"door may hold it. Nothing was sent; resend({record_id!r}) sends that line again, and if "
                "it is this event, a capture under another record_id would record it twice"
            )
        return (
            f"{already} The record kept under it was never sent. Nothing was sent; capture this event "
            "under a record_id of its own"
        )

    def _holds(self, record_id: str, line: bytes) -> bool:
        """Whether the record's line is kept exactly as written."""
        try:
            return self.store.read(self.name(record_id, LINE)) == line
        except OSError:
            return False

    def _withdrawn(self, record_id: str, unwritten: str) -> str:
        """Why the record is not sent, once its marker is withdrawn, or why it could not be."""
        try:
            self.store.remove(f"{OUTBOX}/{checked_record_id(record_id)}")
        except OSError as failed:
            return (
                f"{record_id}: its line could not be written ({unwritten}), and its marker could not be "
                f"withdrawn ({_failure(failed)}). Nothing was sent; if the store kept the line after all, "
                "the next client to send from this evidence sends it, so look with pending() before "
                "recording the event again"
            )
        return (
            f"{record_id}: its line could not be written ({unwritten}). Nothing was sent, and nothing of "
            "it is sent later on its own; its pair is kept"
        )

    def _settled(self, record_id: str) -> None:
        """The record is confirmed or refused: its marker goes. A marker that stays costs one more look."""
        try:
            self.store.remove(f"{OUTBOX}/{checked_record_id(record_id)}")
        except OSError:
            pass

    def _taken(self, record_id: str) -> int:
        """How many of the record's receipts a later receipt took back. 0 unless the door lost it."""
        taken = 0
        while self.store.read(self.name(record_id, _lost(taken))) is not None:
            taken += 1
        return taken

    def confirm(self, record_id: str, receipt: dict[str, Any], leaf_index: int) -> None:
        """Keep the door's receipt beside the pair. A receipt already kept is a confirmation too."""
        unkept = None
        try:
            self.store.create(self.name(record_id, _receipt(self._taken(record_id))), _json(receipt))
        except FileExistsError:
            pass  # another process kept the door's receipt for the same line first
        except OSError as failed:
            unkept = _failure(failed)
        if unkept is not None:
            raise EvidenceError(
                f"{record_id}: the door confirmed it at leaf {leaf_index}, and its receipt could not be "
                f"kept ({unkept}). It is still pending here; resend({record_id!r}) asks again, and the "
                "door recognises it as already held",
                record_id=record_id,
            )
        self._settled(record_id)

    def refuse(self, record_id: str, status: int, said: str) -> bool:
        """Mark the record as refused by the door, so it is not sent again. False if the mark failed.

        A failed mark leaves the record pending, which costs one more refusal on a resend and hides
        nothing; raising here instead would put a storage error where the door's refusal belongs.
        """
        try:
            self.store.create(self.name(record_id, REFUSED), _json({"status": status, "said": said}))
        except FileExistsError:
            pass
        except OSError:
            return False
        self._settled(record_id)
        return True

    def binding_of(self, record_id: str) -> str | None:
        """The fingerprint of the key the record was written under, while it is to be sent."""
        marker = _document(self.store.read(f"{OUTBOX}/{checked_record_id(record_id)}"))
        key = (marker or {}).get("key")
        return key if isinstance(key, str) else None

    def line(self, record_id: str) -> bytes:
        """The exact line a pending record was sent with, while its disclosure still opens it."""
        if not self.is_pending(record_id):
            raise EvidenceError(
                f"{record_id}: not pending in this evidence (no such record, or the door already "
                "confirmed or refused it), so there is nothing to send again",
                record_id=record_id,
            )
        line = self.store.read(self.name(record_id, LINE)) or b""
        sent = _document(line)
        if sent is None or sent.get("record_id") != record_id or not line.endswith(b"\n"):
            raise EvidenceError(
                f"{record_id}: its line.json is not the line this client wrote, so it is not sent. Its "
                "disclosure is untouched",
                record_id=record_id,
            )
        if not _opens(self.store.read(self.name(record_id, DISCLOSURE)), str(sent.get("payload_hash"))):
            raise EvidenceError(
                f"{record_id}: its disclosure.json does not open the address its line commits to, so the "
                "line is not sent: it would record something nobody could ever open",
                record_id=record_id,
            )
        return line

    def is_pending(self, record_id: str) -> bool:
        return (
            self.store.read(self.name(record_id, LINE)) is not None
            and self._kept(record_id) is None
            and self.store.read(self.name(record_id, REFUSED)) is None
        )

    def pending(self, binding: str | None = None) -> list[str]:
        """Every record that was sent and neither confirmed nor refused, in name order.

        ``binding`` narrows it to the records written under that key; None is every key's.
        """
        found = []
        for name in self.store.children(OUTBOX):
            try:
                checked_record_id(name)
            except (TypeError, ValueError):
                continue
            if binding is not None and self.binding_of(name) != binding:
                continue
            if self.store.read(self.name(name, LINE)) is None:
                continue  # committed and never sent: a hole, shown by `gaps`, and nothing to resend
            if self._kept(name) is not None or self.store.read(self.name(name, REFUSED)) is not None:
                self._settled(name)  # left behind by a process that died after the door answered
                continue
            found.append(name)
        return found

    def records(self) -> list[str]:
        """The name of every record kept here, in name order."""
        out = []
        for name in self.store.children(""):
            try:
                out.append(checked_record_id(name))
            except (TypeError, ValueError):
                continue
        return out

    def sent(self, record_id: str) -> dict[str, Any] | None:
        """The line this evidence sent for ``record_id``, or None when it sent no such record."""
        return _document(self.store.read(self.name(record_id, LINE)))

    def _kept(self, record_id: str) -> bytes | None:
        """The bytes of the receipt that stands for ``record_id`` now, when one does."""
        return self.store.read(self.name(record_id, _receipt(self._taken(record_id))))

    def receipt(self, record_id: str) -> dict[str, Any] | None:
        """The door's receipt for ``record_id`` that stands now, when it gave one and it was kept.

        A receipt a later one took back (:meth:`taken_back_by`) does not stand: it is kept, and the
        record is pending until the door gives the next.
        """
        return _document(self._kept(record_id))

    def taken_back_by(self, record_id: str, receipt: dict[str, Any], binding: str) -> list[str]:
        """The records whose receipts ``receipt`` shows the door's log no longer holds; now pending.

        A receipt names the record its record follows (``prev_record_hash``), and in a log that only
        grows one record follows each. So this evidence notes, per record hash, which record it holds
        a receipt for right after it (``.chain/<hash>``); a receipt that puts ANOTHER record after
        the same one is the door's log forking there — rolled back past what it had receipted, and
        written on. The record noted there, and every record noted after it, is gone from the log:
        each gets ``lost.json`` beside its receipt, saying which receipt took it back, and its outbox
        marker again, under ``binding``, so ``pending`` lists it and ``resend`` records it anew from
        the line and the pair kept here. Nothing is removed; the receipt that no longer stands stays.

        Keyed by a record hash, which names one record of one log, so two Environments sharing a
        directory by mistake never take each other's receipts back. The first record of a log follows
        nothing, so a log rolled back to empty is not seen here; nor is a fork after a record whose
        receipt this evidence does not hold, or one kept before this note was.
        """
        after, record_hash = receipt.get("prev_record_hash"), str(receipt.get("record_hash"))
        if not is_content_address(str(after)):
            return []
        follows = {"record_id": record_id, "record_hash": record_hash, "leaf_index": receipt.get("leaf_index")}
        try:
            self.store.create(f"{CHAIN}/{after}", _json(follows))
            return []
        except FileExistsError:
            noted = _document(self.store.read(f"{CHAIN}/{after}"))
        except OSError:
            return []  # the note is an index; a store that cannot take it loses a look, not evidence
        if noted is None or noted.get("record_hash") == record_hash:
            return []
        gone: list[str] = []
        seen = {record_hash}  # a note edited into a circle ends the walk; record hashes cannot form one
        while noted is not None and str(noted.get("record_hash")) not in seen:
            name, was = noted.get("record_id"), str(noted.get("record_hash"))
            if not is_content_address(was):
                break
            seen.add(was)
            if name != record_id and isinstance(name, str) and self._lose(name, was, receipt, binding):
                gone.append(name)
            noted = _document(self.store.read(f"{CHAIN}/{was}"))
        try:
            # The log holds THIS record after that one now, so it is the one to compare the next with.
            self.store.remove(f"{CHAIN}/{after}")
            self.store.create(f"{CHAIN}/{after}", _json(follows))
        except OSError:
            pass
        return gone

    def _lose(self, record_id: str, record_hash: str, by: dict[str, Any], binding: str) -> bool:
        """Note that the door's log no longer holds the record its standing receipt names. False when it
        is not that receipt that stands — already taken back, refused, or never confirmed — or the note
        could not be written, so the record is not claimed to be pending."""
        try:
            checked_record_id(record_id)
        except (TypeError, ValueError):
            return False
        taken = self._taken(record_id)
        standing = _document(self.store.read(self.name(record_id, _receipt(taken))))
        if standing is None or standing.get("record_hash") != record_hash:
            return False
        said = {
            key: by.get(key) for key in ("record_id", "leaf_index", "record_hash", "prev_record_hash", "log_size")
        }
        try:
            self.store.create(self.name(record_id, _lost(taken)), _json({"receipt": _receipt(taken), "taken_back_by": said}))
        except OSError:
            return False  # noted first by another process, which told of it, or not noted at all
        try:
            self.store.create(f"{OUTBOX}/{checked_record_id(record_id)}", _json({"key": binding}))
        except OSError:
            pass  # `resend(record_id)` finds it by its state all the same; `pending` lists what has a marker
        return True

    def file_exhibit(self, record_id: str, files: dict[str, bytes]) -> str:
        """File an exhibit's files in the record's ``exhibit/`` folder, where none is filed yet."""
        if self.store.children(self.name(record_id, EXHIBIT)):
            raise EvidenceError(
                f"{record_id}: an exhibit is already filed here, and it is never replaced. Move it "
                "aside to file another",
                record_id=record_id,
            )
        unfiled = None
        try:
            for name, data in sorted(files.items()):
                self.store.create(self.name(record_id, f"{EXHIBIT}/{name}"), data)
        except FileExistsError:
            unfiled = f"{record_id}: an exhibit was filed here at the same moment, and it is never replaced"
        except OSError as failed:
            unfiled = (
                f"{record_id}: its exhibit could not be written ({_failure(failed)}); what is in "
                f"{self.locate(record_id, EXHIBIT)} is incomplete. Move it aside and take the exhibit again"
            )
        if unfiled is not None:
            raise EvidenceError(unfiled, record_id=record_id)
        return self.locate(record_id, EXHIBIT)
