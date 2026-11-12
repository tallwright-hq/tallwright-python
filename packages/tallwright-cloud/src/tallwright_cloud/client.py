# SPDX-License-Identifier: Apache-2.0
"""Cloud Proof from Python: commit here, keep the pair, send the address, keep the receipt.

    client = Tallwright(ingest_url, archive_key, "./tallwright-evidence")
    captured = client.capture(content, action_type="refund.approved")   # waits for the receipt
    name = client.submit(content, action_type="refund.approved")        # waits for the evidence only

One record, in order:

1. the content is given its one byte form, a 32-byte salt is drawn and the address of
   ``salt ‖ content`` computed (``commit.py``); from here on no frame of this client holds the content;
2. the fields that travel in the clear are checked;
3. the record is named — ``<session>.<number>``, or the caller's own ``record_id`` (``ids.py``);
4. the pair, the outbox marker and the line are written to the evidence store, each durable before
   the next (``evidence.py``);
5. the line — the name, the address and the fields in the clear, never the content or the salt — is
   sent to the recording door (``transport.py``), and sent again, byte for byte, while the answer is
   one that says "not decided";
6. the door's receipt is read strictly and kept beside the pair, and held to the receipts kept
   already: one that puts another record after a record this evidence holds a receipt for shows the
   door lost what it had receipted there, and those records are told and pending again.

**Two ways to wait.** :meth:`Tallwright.capture` does all six before it returns, and raises when the door
did not confirm: for an action that must not run unrecorded. :meth:`Tallwright.submit` returns after
step 4, and a background :class:`~tallwright_cloud.sender.Sender` does 5 and 6: for an agent that must
not wait on the network, a voice agent in the middle of a sentence above all. Both commit, write and
read the door's answer through the same code, so they cannot come to two conclusions about one answer.

**What a Capture is, and what it is not.** The door's confirmation that it holds a record committing
to this address at this leaf of its log — a confirmation, not a proof, in the door's own words. No
witness has seen the record until an anchor covers its leaf, and the proof is the exhibit made after
that, checked by the public verifier together with the disclosure kept here. Nor does a capture say
anything about the actions nobody captured: integrity of what was recorded, not completeness of what
happened.

**After NotConfirmed, resend; never capture again.** A capture is a new record with a new salt. Wrapped
in a retry loop of the caller's own, an answer that was lost becomes the same event recorded twice.
``submit`` never needs one: what it queued is sent until the door decides.

**What the door sees.** The address, the record's name, and ``action_type``, ``actor_authority`` and
``timestamp`` when they are given — those three in the clear, sealed into every exhibit, so they name
kinds of events and authorities, never people. Never the content, never the salt.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Self

from tallwright_core.canonical import canonicalize

from . import exhibit, transport
from .commit import Commitment, Refusal
from .errors import (
    AccountClosed,
    EvidenceError,
    ExhibitError,
    LostByTheDoor,
    NotConfirmed,
    RecordIdConflict,
    Refused,
    TallwrightError,
    Unauthorized,
)
from .evidence import DISCLOSURE, Evidence
from .ids import Minter, checked_record_id
from .receipt import Receipt, UnreadableReceipt
from .sender import Flushed, Sender
from .store import EvidenceStore, store_of

#: The answers that decide nothing about the line: the same bytes are sent again.
RETRY = frozenset({408, 425, 429, 500, 502, 503, 504})
#: The waits between attempts of ``capture``: four attempts in all, three and a half seconds of waiting.
DELAYS = (0.5, 1.0, 2.0)
#: How the door begins its sentence when it refuses a line for what the line says
#: (https://docs.tallwright.com/http). Its other 400s are about the batch or the door, and a resend may succeed.
_LINE_REFUSED = re.compile(r"line \d+ is not a usable record")
#: ``action_type`` and ``actor_authority``: a kind or a name of a rule, not a sentence. No space and no
#: ``@``, so the easy mistakes — a person's name, an address — are refused before they are sealed.
_CLEAR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}")
#: RFC 3339, section 5.6: a date, a ``T``, a time with optional fractions, and its offset. The standard
#: library's ISO reader takes more than this (week dates, basic format, any separator), and one of the
#: separators it takes ends a line where the door splits its body.
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")
#: How an account key begins (``account.py``). It makes and closes Environments, and the code that
#: records or takes exhibits never holds one: given here by mistake, it is refused before it is sent.
_ACCOUNT_KEY = "ta_"

#: The wait between attempts; a test replaces it rather than sleeping.
_pause = time.sleep
#: How often the sending thread asks the store for its outbox before it leaves the backlog for the next
#: request, and the first wait between: a throttled LIST (SlowDown) is answered at the next ask.
_LOOKS, _FIRST_LOOK_WAIT = 3, 0.2

log = logging.getLogger("tallwright_cloud")

#: What ``on_problem`` is called with: the error, which names the record and never its content.
Problem = Callable[[TallwrightError], None]


def _filed(evidence: Evidence, files: dict[str, bytes], asked: str | None = None) -> str:
    """File an exhibit beside the record it is of, if it is the exhibit of a record this evidence sent;
    where it was filed. ``asked``, when an export key asked for one record: the exhibit must be of that one.

    Filed only if it says what the line said (``exhibit.what_differs``) and — where the door's receipt
    was kept — at the leaf, under the record hash and at the time the receipt named. Checking the exhibit
    itself is the public verifier's job, with ``Capture.disclosure``: this says only that it is the exhibit
    of this record.
    """
    held = exhibit.held_in(files["evidence.json"])
    record_id = held.record.record_id
    if asked is not None and record_id != asked:
        raise ExhibitError(
            f"{asked}: the door answered with the exhibit of another record, {record_id!r}. Nothing was filed",
            record_id=asked,
        )
    try:
        name = checked_record_id(record_id)
    except (TypeError, ValueError):
        name = ""
    sent = evidence.sent(name) if name else None
    if sent is None:
        raise ExhibitError(
            f"the exhibit is of record {record_id!r}, which this evidence did not send. Nothing was filed",
            record_id=record_id,
        )
    if differs := exhibit.what_differs(held, sent):
        raise ExhibitError(
            f"{name}: the exhibit's record differs from the line this evidence sent in "
            f"{', '.join(differs)}: it is not the record of this capture. Nothing was filed",
            record_id=name,
        )
    receipt = evidence.receipt(name)
    if receipt is not None and (
        receipt.get("leaf_index"),
        receipt.get("record_hash"),
        receipt.get("timestamp"),
    ) != (held.leaf_index, held.record_hash, held.record.timestamp):
        raise ExhibitError(
            f"{name}: the door's receipt named leaf {receipt.get('leaf_index')}, record "
            f"{receipt.get('record_hash')} at {receipt.get('timestamp')}, and the exhibit names leaf "
            f"{held.leaf_index}, record {held.record_hash} at {held.record.timestamp}. Nothing was filed",
            record_id=name,
        )
    return evidence.file_exhibit(name, files)


@dataclass(frozen=True)
class Capture:
    """A record the door confirmed holding: its name, its address, the receipt and where its pair is."""

    record_id: str
    payload_hash: str
    receipt: Receipt
    #: Where the record's evidence is: its folder, or its prefix in a bucket.
    evidence: str
    #: Where its disclosure is: what `evidence-verify --disclosure` reads to open the address.
    disclosure: str
    #: The door's warning when it holds the record and something on its side needs repair; or this
    #: client's, when the receipt contradicts a receipt the evidence already keeps (the door's log lost
    #: records it had confirmed).
    warning: str | None = None


def line_for(
    record_id: str,
    payload_hash: str,
    *,
    action_type: str | None = None,
    actor_authority: str | None = None,
    timestamp: str | None = None,
) -> bytes:
    """The one line the door is sent: RFC 8785, so the same fields are the same bytes whoever sends them.

    The HTTP contract (https://docs.tallwright.com/http) writes it by hand in this order, and a test holds
    the two to each other.
    """
    fields = {"record_id": record_id, "payload_hash": payload_hash}
    for key, value in (("action_type", action_type), ("actor_authority", actor_authority), ("timestamp", timestamp)):
        if value is not None:
            fields[key] = value
    return canonicalize(fields) + b"\n"


def _clear(name: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} is text, not {type(value).__name__}")
    if not _CLEAR.fullmatch(value):
        raise ValueError(
            f"{name} travels in the clear and is sealed into every exhibit, so it names a kind or a "
            "rule: 1 to 128 of A-Z a-z 0-9 . _ : / + -, starting with a letter or a digit, no spaces "
            "and no @. This one is not, and it is not repeated here"
        )
    return value


def _not_an_account_key(key: transport.Key, wanted: str) -> transport.Key:
    """``key``, unless it is an account key. Called once the caller's frame no longer holds the key."""
    if key.reveal().startswith(_ACCOUNT_KEY):
        raise ValueError(
            "this is an account key (ta_…): it makes and closes Environments, and it never belongs in "
            f"the process that records, so it is neither kept nor sent here. Give {wanted} instead"
        )
    return key


def _moment(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"timestamp is RFC 3339 text, not {type(value).__name__}")
    try:
        valid = bool(_RFC3339.fullmatch(value)) and datetime.fromisoformat(value) is not None
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(
            f"timestamp {value!r} is not an RFC 3339 time with its offset (2026-10-08T09:30:12+02:00). "
            "Leave it out and the door stamps the moment it first takes the record"
        )
    return value


def _untrusted(failed: Exception) -> bool:
    return isinstance(getattr(failed, "reason", failed), ssl.SSLCertVerificationError)


def _described(failed: Exception) -> str:
    reason = getattr(failed, "reason", None)
    return f"{type(failed).__name__}: {reason if reason is not None else failed}"


def _unread(failed: OSError) -> str:
    return str(failed.strerror or failed)


@dataclass(frozen=True)
class _Untrusted:
    """The door's certificate did not verify: nothing was sent, and nothing will be until it does.

    It decides nothing about any record, so the background sending tries again like any such answer: a
    clock that is behind at boot, or a chain the door serves incomplete for a minute, costs a wait, not
    the sending of the rest of the process. ``capture`` says it at once.
    """

    why: str = (
        "the door's certificate did not verify, so nothing was sent to it, the key included. Check the "
        "address, or this machine's trust store"
    )


@dataclass(frozen=True)
class Status:
    """What a client's background sending is doing now."""

    #: Records submitted and not yet confirmed or refused by the door, in this process.
    queued: int
    #: Why sending stopped for this client, when it did; its records stay pending in the evidence.
    stopped: str | None


class Tallwright:
    """A client of one recording door, keeping the evidence of its records in one store.

    ``url`` is the ingest address the backoffice gives (``https://…``, a book beneath the host
    included), ``key`` the archive key shown once when the environment was made, ``evidence`` where the
    pairs are kept: a directory, or an :class:`~tallwright_cloud.store.EvidenceStore` such as
    :class:`~tallwright_cloud.store.S3Evidence`. It is required, because a salt kept only in memory is
    lost with the process, and a record whose salt is lost can never be opened again.

    ``on_problem`` is called, from the sending thread, with every problem background sending meets:
    a record the door refused, a key it does not hold, an answer that decided nothing, a store that
    could not be read. It is told once per streak, not once per attempt, and the ``tallwright_cloud``
    logger is told in any case. It is also called, from whichever thread kept the receipt, ``capture``
    included, with :class:`~tallwright_cloud.errors.LostByTheDoor` when a receipt shows the door lost
    records it had confirmed.
    """

    def __init__(
        self,
        url: str,
        key: str,
        evidence: str | os.PathLike[str] | EvidenceStore,
        *,
        timeout: float = 30.0,
        on_problem: Problem | None = None,
        sender: Sender | None = None,
    ) -> None:
        held = transport.Key(key)
        del key  # from here on no frame of this client holds the key, only its Key, whose repr is its face
        self._key = _not_an_account_key(held, "the archive key of the Environment it records into")
        self._endpoint = transport.endpoint(url)
        self.url = url
        self._binding = self._key.binding()
        self._timeout = timeout
        try:
            self._store = store_of(evidence)
        except OSError as failed:
            raise EvidenceError(
                f"the evidence {str(evidence)!r} cannot be used ({failed.strerror or failed}). "
                "Nothing was sent: without it, a salt would exist only in memory"
            ) from None
        self._evidence = Evidence(self._store)
        self._minter = Minter()
        self._on_problem = on_problem
        self._sender = sender
        self._own_sender = sender is None
        #: Whether what an earlier process left pending under this key was taken on (``_take_on``).
        self._resumed = False
        # Whether the streak going on now was told: of answers that decide nothing, and of a store that
        # cannot be read. Each is told once, when it begins.
        self._failing = False
        self._unreadable = False
        self._closed = False

    def __repr__(self) -> str:
        return f"Tallwright(url={self.url!r}, key={self._key!r}, evidence={self._store!r})"

    def __enter__(self) -> Self:
        return self

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None, trace: TracebackType | None) -> None:
        self.close()

    @property
    def session(self) -> str:
        """The sixteen hex digits every name this client mints in this process begins with."""
        return self._minter.session

    @property
    def evidence(self) -> EvidenceStore:
        """The store this client keeps its evidence in: the content, the salt, the line and the receipt."""
        return self._store

    # --- recording ---------------------------------------------------------------------------------

    def _kept(
        self,
        committed: Commitment,
        action_type: str | None,
        actor_authority: str | None,
        record_id: str | None,
        timestamp: str | None,
    ) -> tuple[str, str, bytes, str]:
        """Steps 2 to 4: the record's name, its address, its line and where its evidence is."""
        named = None if record_id is None else checked_record_id(record_id)
        action, authority = _clear("action_type", action_type), _clear("actor_authority", actor_authority)
        moment = _moment(timestamp)
        name = named if named is not None else self._minter.next()
        line = line_for(
            name, committed.payload_hash, action_type=action, actor_authority=authority, timestamp=moment
        )
        where = self._evidence.begin(name, committed, line, self._binding)
        return name, committed.payload_hash, line, where

    def capture(
        self,
        content: object,
        *,
        action_type: str | None = None,
        actor_authority: str | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
    ) -> Capture:
        """Record one event and wait for the door's receipt: the content stays here, its address goes.

        ``action_type`` makes it an action the agent triggered; without it, it is context the agent
        received. Everything is checked before anything is written, and nothing is sent before the
        pair is safe. Raises when the door did not confirm it; see the module docstring for what then.
        """
        # Step 1, and from here on no frame of this client holds the content: an error raised below,
        # and every error an error tracker records with the local variables of its frames, carries the
        # Commitment at most, whose repr is the address alone.
        committed = Commitment.of(content)
        del content
        if isinstance(committed, Refusal):
            raise committed.error()
        return self._capture(committed, action_type, actor_authority, record_id, timestamp)

    def _capture(
        self,
        committed: Commitment,
        action_type: str | None,
        actor_authority: str | None,
        record_id: str | None,
        timestamp: str | None,
    ) -> Capture:
        name, payload_hash, line, where = self._kept(committed, action_type, actor_authority, record_id, timestamp)
        del committed
        return self._send(name, payload_hash, line, where, fresh=True)

    def submit(
        self,
        content: object,
        *,
        action_type: str | None = None,
        actor_authority: str | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        """Record one event without waiting for the door; its name, once its evidence is safe.

        The same checks and the same evidence as :meth:`capture`; the line is sent in the background
        (``sender.py``), and :meth:`flush` waits for it. A problem the door reports later goes to
        ``on_problem`` and the logger; the record stays in the evidence either way.
        """
        # Step 1, and from here on no frame of this client holds the content: an error raised below,
        # and every error an error tracker records with the local variables of its frames, carries the
        # Commitment at most, whose repr is the address alone.
        committed = Commitment.of(content)
        del content
        if isinstance(committed, Refusal):
            raise committed.error()
        return self._submit(committed, action_type, actor_authority, record_id, timestamp)

    def _submit(
        self,
        committed: Commitment,
        action_type: str | None,
        actor_authority: str | None,
        record_id: str | None,
        timestamp: str | None,
    ) -> str:
        name, _, _, _ = self._kept(committed, action_type, actor_authority, record_id, timestamp)
        del committed
        self._queue([name])
        return name

    async def acapture(
        self,
        content: object,
        *,
        action_type: str | None = None,
        actor_authority: str | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
    ) -> Capture:
        """:meth:`capture`, from a coroutine: committed here, written and sent off the event loop."""
        # Step 1, and from here on no frame of this client holds the content: an error raised below,
        # and every error an error tracker records with the local variables of its frames, carries the
        # Commitment at most, whose repr is the address alone.
        committed = Commitment.of(content)
        del content
        if isinstance(committed, Refusal):
            raise committed.error()
        return await asyncio.to_thread(self._capture, committed, action_type, actor_authority, record_id, timestamp)

    async def asubmit(
        self,
        content: object,
        *,
        action_type: str | None = None,
        actor_authority: str | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        """:meth:`submit`, from a coroutine: committed here, the evidence written off the event loop."""
        # Step 1, and from here on no frame of this client holds the content: an error raised below,
        # and every error an error tracker records with the local variables of its frames, carries the
        # Commitment at most, whose repr is the address alone.
        committed = Commitment.of(content)
        del content
        if isinstance(committed, Refusal):
            raise committed.error()
        return await asyncio.to_thread(self._submit, committed, action_type, actor_authority, record_id, timestamp)

    def _queue(self, names: list[str]) -> None:
        if self._closed:
            raise TallwrightError(
                f"{names[0]}: its evidence is kept and it is pending, and this client was closed, so it "
                "is not sent from here. A new client on the same evidence sends it",
                record_id=names[0],
            )
        if self._sender is None:
            self._sender = Sender()
        # Only the caller's own names: what an earlier process left pending is taken on by the sending
        # thread (``_take_on``), so a submit never waits for a scan of the store, nor fails with it.
        self._sender.put(self, names)

    def flush(self, timeout: float | None = 30.0) -> Flushed:
        """Wait up to ``timeout`` seconds for what was submitted; what is still to be sent, and why."""
        if self._sender is None:
            return Flushed(0)
        return self._sender.flush(timeout, self)

    def close(self, timeout: float | None = 10.0) -> Flushed:
        """Flush, and end this client's own sending thread. What is left stays pending in the evidence."""
        self._closed = True
        if self._sender is None:
            return Flushed(0)
        if self._own_sender:
            return self._sender.close(timeout)
        return self._sender.flush(timeout, self)

    def status(self) -> Status:
        """What this client's background sending is doing now: how many records wait, and why it stopped."""
        if self._sender is None:
            return Status(0, None)
        return Status(self._sender.queued(self), self._sender.stopped(self))

    # --- what is pending ---------------------------------------------------------------------------

    def pending(self) -> list[str]:
        """Records sent under this key and never confirmed or refused, which ``resend`` may send again."""
        return self._evidence.pending(self._binding)

    def resend(self, record_id: str, *, adopt: bool = False) -> Capture:
        """Send a pending record's line again, byte for byte. Already held is a confirmation too.

        A record pending under ANOTHER key is sent with this one only with ``adopt``: when the key was
        replaced and this is the same Environment, which only the caller can know.
        """
        name = checked_record_id(record_id)
        line = self._evidence.line(name)
        bound = self._evidence.binding_of(name)
        if bound != self._binding and not adopt:
            # A marker that is gone or unreadable says no key at all: not this one, so not sent with it.
            raise EvidenceError(
                f"{name}: it was written under another key, so it is not sent with this one. If this key "
                "replaced that one for the same Environment, resend it with adopt=True"
                if bound is not None
                else f"{name}: its outbox marker is gone or unreadable, so the key it was written under is "
                "not known, and it is not sent with this one. If it is a record of this key's Environment, "
                "resend it with adopt=True",
                record_id=name,
            )
        payload_hash = str(json.loads(line)["payload_hash"])
        return self._send(name, payload_hash, line, self._evidence.locate(name), fresh=False)

    def resend_pending(self, *, timeout: float | None = 30.0) -> Flushed:
        """Lift a stop, queue every record pending under this key for the background sender, and flush.

        The person's act after a 401 or a 403: once the key or the account is right again, this sends what
        waited, each record once, and later submits are sent again.
        """
        names = self.pending()
        self._resumed = True
        if self._sender is not None:
            self._sender.resume(self)
        if names:
            if self._sender is None:
                self._sender = Sender()
            self._sender.put(self, names)
        return self.flush(timeout)

    def save_exhibit(self, link: str) -> str:
        """Open a one-time exhibit link and file the exhibit beside the record it is of; where it is.

        Filed only if it is of a record this evidence sent, saying what the line said (see
        ``exhibit.what_differs``), and — where the door's receipt was kept — at the leaf, under the
        record hash and at the time the receipt named. Checking the exhibit itself is the public
        verifier's job, with ``Capture.disclosure``: this says only that it is the exhibit of this record.
        """
        return _filed(self._evidence, exhibit.unpacked(exhibit.fetch(link, self._timeout)))

    # --- talking to the door -------------------------------------------------------------------------

    def _post(self, body: bytes) -> transport.Answer | _Untrusted | str:
        """One request: the answer, a refusal to send at all, or why there was no answer."""
        try:
            return transport.post(self._endpoint, self._key, body, self._timeout)
        except (OSError, http.client.HTTPException) as failed:
            return _Untrusted() if _untrusted(failed) else _described(failed)

    def _deliver(self, record_id: str, line: bytes) -> tuple[transport.Answer, int]:
        last, attempts = "", 0
        last_status: int | None = None
        for wait in (0.0, *DELAYS):
            if wait:
                _pause(wait)
            attempts += 1
            answer = self._post(line)
            if isinstance(answer, _Untrusted):
                raise NotConfirmed(record_id, answer.why)
            if isinstance(answer, str):
                last, last_status = answer, None
                continue
            if answer.status in RETRY:
                said = transport.said(answer)
                last, last_status = f"it answered {answer.status} ({said or 'no sentence'})", answer.status
                continue
            return answer, attempts
        raise NotConfirmed(record_id, f"{attempts} attempts, the last: {last}", status=last_status)

    def _send(self, record_id: str, payload_hash: str, line: bytes, where: str, *, fresh: bool) -> Capture:
        answer, attempts = self._deliver(record_id, line)
        outcome = self._verdict(answer, record_id, payload_hash, line, where, fresh=fresh and attempts == 1)
        if isinstance(outcome, TallwrightError):
            raise outcome
        return outcome

    def _verdict(
        self, answer: transport.Answer, record_id: str, payload_hash: str, line: bytes, where: str, *, fresh: bool
    ) -> Capture | TallwrightError:
        """What one answer to one line means: the one reading of the door, for ``capture`` and the sender."""
        status, said = answer.status, transport.said(answer)
        if status == 200:
            body = answer.body or {}
            receipts = body.get("receipts")
            if not isinstance(receipts, list) or len(receipts) != 1:
                many = f" ({len(receipts)} receipts for one line)" if isinstance(receipts, list) and receipts else ""
                return NotConfirmed(record_id, f"the door answered 200 without a receipt for it{many}", status=200)
            warning = body.get("warning")
            return self._confirmed(record_id, payload_hash, line, where, receipts[0], warning if isinstance(warning, str) else None)
        if said is not None and status == 409:
            self._evidence.refuse(record_id, status, said)
            return RecordIdConflict(
                record_id,
                said,
                status=status,
                meaning="The log holds a different record under this name, so nothing of this capture was "
                "recorded; capture it under a name of its own"
                if fresh
                else "This send recorded nothing, and the log holds a different record under this name. "
                "Whether that is an earlier send of this same line cannot be told from the answer: an "
                "exhibit of the record shows which. Sending it again cannot change the answer",
            )
        if said is not None and status == 400 and _LINE_REFUSED.match(said):
            self._evidence.refuse(record_id, status, said)
            return Refused(
                record_id,
                said,
                status=status,
                meaning="The door read the line and refused what it says, so nothing of it was recorded, "
                "and the same line will not be accepted; a new capture is a new record",
            )
        told = f" ({said})" if said is not None else ", without the door's sentence"
        if status == 401:
            return Unauthorized(record_id, f"the door does not hold this key (401{told})", status=status)
        if status == 403:
            return AccountClosed(record_id, f"the account behind this key is closed (403{told})", status=status)
        if 300 <= status < 400:
            return NotConfirmed(
                record_id,
                f"the door answered with a redirect ({status}) to {answer.location!r}, which is not "
                "followed: it would carry the key to an address nobody configured. Configure the "
                "address it names, if that is the door",
                status=status,
            )
        return NotConfirmed(record_id, f"the answer was {status}{told}", status=status)

    def _confirmed(
        self, record_id: str, payload_hash: str, line: bytes, where: str, given: object, warning: str | None
    ) -> Capture | NotConfirmed:
        try:
            receipt: Receipt | None = Receipt.read(given, record_id)
            why = ""
        except UnreadableReceipt as unread:
            receipt, why = None, str(unread)
        stated = json.loads(line).get("timestamp")
        if receipt is not None and stated is not None and receipt.timestamp != stated:
            why = f"the line stated the time {stated!r} and the receipt names {receipt.timestamp!r}"
            receipt = None
        if receipt is None:
            return NotConfirmed(
                record_id, f"the door answered 200, and what it sent is not its receipt for it: {why}", status=200
            )
        self._evidence.confirm(record_id, receipt.as_written, receipt.leaf_index)
        # Held to the receipts kept already, because this evidence is the one party that can: a log put
        # back to a state after its last anchor took the records receipted since with it, and the door's
        # own checks, its alarm and the witness all agree with what is left. Not raised: this record IS
        # held; the ones it shows lost are pending again and are told.
        gone = self._evidence.taken_back_by(record_id, receipt.as_written, self._binding)
        if gone:
            self._problem(LostByTheDoor(gone, record_id, receipt.leaf_index))
        return Capture(record_id, payload_hash, receipt, where, self._evidence.locate(record_id, DISCLOSURE), warning)

    def _problem(self, problem: TallwrightError, *, quietly: bool = False) -> None:
        """Tell the logger, and ``on_problem``, about something the sending met."""
        level = logging.INFO if quietly else logging.WARNING
        log.log(level, "tallwright_cloud: %s: %s", type(problem).__name__, problem)
        if self._on_problem is not None:
            try:
                self._on_problem(problem)
            except Exception:  # noqa: BLE001 - a broken callback must not stop the sending
                log.exception("tallwright_cloud: on_problem raised; sending goes on")

    def _deliver_batch(self, names: list[str], limit: int) -> tuple[list[str], str | None]:
        """One request for the sender: the names to send again later, and why to stop, if it must.

        A 200 is read line by line, each against its own receipt. Any other answer that is the same for
        every line (no answer, a busy door, a key the door does not hold) is taken for all of them; an
        answer that could be about one line of several is never guessed at: the lines go one by one,
        so each answer is about exactly one. Names past ``limit`` bytes wait for the next request.

        The store is read here, in the sending thread, and nowhere does a failure to read it leave this
        method: a record that cannot be read now waits and is sent again later, without holding back the
        others, and the streak is told once, like a door's.
        """
        trouble = None if self._resumed else self._take_on(names)
        lines: list[tuple[str, bytes, str]] = []
        unread: list[str] = []
        size, cut = 0, len(names)
        for index, name in enumerate(names):
            try:
                line = self._line_of(name)
            except OSError as failed:
                unread.append(name)
                trouble = trouble or EvidenceError(
                    f"{name}: its evidence could not be read ({_unread(failed)}). Nothing is lost: it and "
                    "every record that cannot be read now wait, and are sent once the store answers",
                    record_id=name,
                )
                continue
            if line is None:
                continue
            if lines and size + len(line) > limit:
                cut = index
                break
            lines.append((name, line, str(json.loads(line)["payload_hash"])))
            size += len(line)
        if trouble is not None and not self._unreadable:
            self._problem(trouble)
        self._unreadable = trouble is not None
        again, stop = self._settle(lines) if lines else ([], None)
        if stop is not None:
            return [], stop
        waiting = {*unread, *again}
        return [*(name for name in names[:cut] if name in waiting), *names[cut:]], None

    def _take_on(self, names: list[str]) -> EvidenceError | None:
        """Queue what an earlier process left pending under this key, behind what this one queued.

        Once per client, in the sending thread. A store that refuses the listing is asked again at once,
        with a short wait between (a throttled LIST is answered at the next ask); one that still cannot
        be listed is looked at again with the next request, and what it holds stays pending meanwhile.
        """
        looks = 0
        while True:
            try:
                earlier = [name for name in self.pending() if name not in names]
                break
            except OSError as failed:
                looks += 1
                if looks == _LOOKS:
                    return EvidenceError(
                        f"what an earlier process left pending under this key could not be listed "
                        f"({_unread(failed)}). It stays pending in the evidence and is looked for again with "
                        "the next request; resend_pending() sends it once the store answers"
                    )
                _pause(_FIRST_LOOK_WAIT * 2 ** (looks - 1))
        self._resumed = True
        assert self._sender is not None  # the sender is the one calling
        if earlier:
            try:
                self._sender.put(self, earlier)
            except TallwrightError:
                pass  # closed meanwhile: what is pending stays pending, for the next client on this evidence
        return None

    def _line_of(self, name: str) -> bytes | None:
        """A queued record's line, or None when it is not to be sent; OSError when the store cannot say."""
        try:
            return self._evidence.line(name)
        except EvidenceError as unsendable:
            if self._evidence.sent(name) is None or self._evidence.is_pending(name):
                self._problem(unsendable)
            else:
                # Confirmed or refused meanwhile, by another client on the same evidence and key (a
                # replica, a worker): nothing is wrong, and nothing is left to send.
                log.debug("tallwright_cloud: %s was settled by another client of this evidence", name)
            return None

    def _settle(self, lines: list[tuple[str, bytes, str]]) -> tuple[list[str], str | None]:
        names = [name for name, _, _ in lines]
        answer = self._post(b"".join(line for _, line, _ in lines))
        if isinstance(answer, _Untrusted):
            return self._undecided(names, answer.why)
        if isinstance(answer, str):
            return self._undecided(names, f"no answer ({answer})")
        if answer.status in RETRY:
            return self._undecided(names, f"it answered {answer.status} ({transport.said(answer) or 'no sentence'})")
        if answer.status in (401, 403) or 300 <= answer.status < 400:
            name, line, payload_hash = lines[0]
            verdict = self._verdict(answer, name, payload_hash, line, self._evidence.locate(name), fresh=False)
            assert isinstance(verdict, TallwrightError)
            return [], self._stopped(verdict)
        receipts = (answer.body or {}).get("receipts") if answer.status == 200 else None
        if len(lines) > 1 and not (isinstance(receipts, list) and len(receipts) == len(lines)):
            again: list[str] = []
            for one in lines:
                more, stop = self._settle([one])
                if stop is not None:
                    return [], stop
                again.extend(more)
            return again, None
        warning = (answer.body or {}).get("warning")
        again = []
        for index, (name, line, payload_hash) in enumerate(lines):
            outcome: Capture | TallwrightError
            if answer.status == 200 and isinstance(receipts, list) and len(receipts) == len(lines):
                try:
                    outcome = self._confirmed(
                        name, payload_hash, line, self._evidence.locate(name), receipts[index],
                        warning if isinstance(warning, str) else None,
                    )
                except EvidenceError as unkept:
                    # The door holds it and its receipt could not be kept: still pending here, and the
                    # next send is recognised as already held.
                    outcome = unkept
            else:
                outcome = self._verdict(answer, name, payload_hash, line, self._evidence.locate(name), fresh=False)
            if isinstance(outcome, Capture):
                if outcome.warning:
                    log.warning("tallwright_cloud: %s is held, and the door warns: %s", name, outcome.warning)
                continue
            if isinstance(outcome, Refused):
                self._problem(outcome)
                continue
            again.append(name)
            if not self._failing:
                self._problem(outcome)
                self._failing = True
        self._failing = bool(again)
        return again, None

    def _undecided(self, names: list[str], why: str) -> tuple[list[str], None]:
        if not self._failing:
            self._problem(NotConfirmed(names[0], f"{len(names)} record(s) not confirmed yet: {why}", sending_again=True))
        self._failing = True
        return names, None

    def _stopped(self, why: TallwrightError) -> str:
        self._problem(why)
        return f"{type(why).__name__}: {why}"


class Exhibits:
    """An environment's exhibits, taken with its export key, filed beside the records this evidence sent.

        exhibits = Exhibits(exhibits_url, export_key, "./tallwright-evidence")
        exhibits.save(captured.record_id)   # where it was filed: <record_id>/exhibit/

    No link and no click: the exhibit door answers the export key with the exhibit of one record
    of its environment. A separate object from :class:`Tallwright`, on purpose. The code that records needs
    no credential that reads, and an export key held where the agent runs is one the agent can lose; keep it
    where the exhibits are wanted. ``url`` is the environment's exhibit address the backoffice gives
    (``https://…``, a book beneath the host included), ``export_key`` the key shown once when it was made,
    ``evidence`` the store the capturing client kept the pairs in: an exhibit is filed only beside a
    record that store sent, saying what its line said.
    """

    def __init__(
        self, url: str, export_key: str, evidence: str | os.PathLike[str] | EvidenceStore, *, timeout: float = 30.0
    ) -> None:
        held = transport.Key(export_key)
        del export_key  # from here on no frame holds the key, only its Key, whose repr is its face
        self._key = _not_an_account_key(held, "the export key of the Environment whose exhibits it takes")
        transport.checked_address(url, "the exhibit door")
        self.url = url
        self._timeout = timeout
        try:
            self._store = store_of(evidence)
        except OSError as failed:
            raise EvidenceError(f"the evidence {str(evidence)!r} cannot be used ({failed.strerror or failed})") from None
        self._evidence = Evidence(self._store)

    def __repr__(self) -> str:
        return f"Exhibits(url={self.url!r}, export_key={self._key!r}, evidence={self._store!r})"

    @property
    def evidence(self) -> EvidenceStore:
        """The store the exhibits are filed in, beside the records this evidence sent."""
        return self._store

    def save(self, record_id: str) -> str:
        """Take the exhibit of one record this evidence sent and file it beside the record; where it is.

        Asked for only a record this evidence sent, so a typo costs no request; and filed only if the
        door answered with the exhibit of THAT record, saying what its line said (see ``save_exhibit``).
        ``ExportKeyRefused`` (401), ``ExhibitNotReady`` (409, not witnessed yet: ask again after the next
        anchor run), ``ExhibitError`` otherwise, with the door's sentence. Nothing is spent by asking.
        """
        name = checked_record_id(record_id)
        if self._evidence.sent(name) is None:
            raise ExhibitError(
                f"{name}: this evidence did not send that record, so its exhibit was not asked for",
                record_id=name,
            )
        files = exhibit.unpacked(exhibit.take(self.url, self._key, name, self._timeout))
        return _filed(self._evidence, files, asked=name)
