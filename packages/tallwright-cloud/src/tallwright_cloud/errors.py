# SPDX-License-Identifier: Apache-2.0
"""What a capture can end in besides a receipt, as two kinds that call for opposite things.

**NotConfirmed: send it again.** No receipt came back for the record: the door was unreachable, the
answer was lost, it answered with something that is not a receipt, the key, the account or the address
was wrong, or something between the client and the door refused the request. The record is pending in
the evidence directory, and ``resend`` sends the same line, byte for byte — a record the door already
holds is recognised by its ``record_id`` and not written twice. Nothing here says whether the door holds
it; that is the point of the word.

**Refused: do not.** The door itself read the line and refused it, in its own sentence: a field it will
not take (400, naming the line), or a ``record_id`` it holds for a different record (409). Sending the
same line again asks the same question for the same answer. A refusal that does not come with the
door's sentence is not taken for one: a proxy's 400 says nothing about the line.

**LostByTheDoor: send them again, and say so.** Not an end of a capture but something a receipt
showed: records the door had confirmed are gone from its log. They are pending again, and it reaches
``on_problem`` and the logger rather than being raised, because the capture whose receipt showed it
was recorded.

Every message names the record and what to do, and none carries the content, the salt or the key:
a message is the one thing an integrator pastes into a ticket.
"""

from __future__ import annotations


class TallwrightError(Exception):
    """Anything this client refuses or could not complete. ``record_id`` says which record, or ``""``."""

    def __init__(self, message: str, *, record_id: str = "", status: int | None = None) -> None:
        super().__init__(message)
        self.record_id = record_id
        #: The door's HTTP status, when an answer arrived at all.
        self.status = status


class NotConfirmed(TallwrightError):
    """No receipt for this record. It is pending, and ``resend(record_id)`` may be called.

    ``sending_again`` is for the background sender, which tells this to ``on_problem`` while it sends
    the record again on its own: the sentence then says that, instead of asking for a resend.
    """

    def __init__(self, record_id: str, why: str, *, status: int | None = None, sending_again: bool = False) -> None:
        what_now = (
            "It is pending in the evidence and is sent again on its own, the same bytes; a record the door "
            "already holds is recognised by its record_id, not written twice"
            if sending_again
            else f"It is pending in the evidence directory; resend({record_id!r}) sends the same line again, "
            "and a record the door already holds is recognised by its record_id, not written twice. Do not "
            "capture it again: a new capture is a new record"
        )
        super().__init__(
            f"{record_id}: not confirmed: {why}. Whether the door holds it is not known here. {what_now}",
            record_id=record_id,
            status=status,
        )


class Unauthorized(NotConfirmed):
    """401: the key is not one the door holds. Pending, bound to the key it was written under: once the
    right key is in place, ``resend(record_id, adopt=True)`` sends it under that key."""

    def __init__(self, record_id: str, why: str, *, status: int | None = None) -> None:
        TallwrightError.__init__(
            self,
            f"{record_id}: not confirmed: {why}. It is pending in the evidence directory, bound to the key it "
            f"was written under. Once the right key is in place, resend({record_id!r}, adopt=True) sends it "
            "under that key; if the door takes this key again, resend_pending() sends it. Do not capture it "
            "again: a new capture is a new record",
            record_id=record_id,
            status=status,
        )


class AccountClosed(NotConfirmed):
    """403: the account behind the key is closed. Pending; nothing is recorded until it reopens."""


class Refused(TallwrightError):
    """The door read this line and refused it in its own sentence. Not pending; the same line will not
    be accepted."""

    def __init__(self, record_id: str, said: str, *, status: int, meaning: str) -> None:
        super().__init__(
            f"{record_id}: refused with {status}: {said}. {meaning}",
            record_id=record_id,
            status=status,
        )
        #: The door's own sentence.
        self.said = said


class RecordIdConflict(Refused):
    """409: the door holds a record under this ``record_id`` that differs from this line."""


class LostByTheDoor(TallwrightError):
    """Records the door receipted and its log no longer holds. Pending again; ``resend`` records each anew.

    Seen in a later receipt: it puts another record after the record one of these followed, and a log
    that only grows has one record there. So the log was rolled back past what it had confirmed — a
    restore, or a power cut that took it back cleanly — and written on. The evidence still holds each
    record's line and pair, and the receipt that no longer stands beside them.
    """

    def __init__(self, record_ids: list[str], by: str, leaf_index: int) -> None:
        shown = ", ".join(record_ids[:10]) + (f" and {len(record_ids) - 10} more" if len(record_ids) > 10 else "")
        super().__init__(
            f"{shown}: the door confirmed {len(record_ids)} record(s) that its log no longer holds. The "
            f"receipt for {by} puts it at leaf {leaf_index}, after the record the first of them followed, "
            "so the log was rolled back past them and written on. Each is pending in the evidence again: "
            "resend(record_id) records it anew from the line and the pair kept here, and the receipt that "
            "no longer stands is kept beside them. Tell the door's operator what was lost",
            record_id=record_ids[0],
        )
        #: Every record the door lost, in the order of the log it lost them from.
        self.record_ids = tuple(record_ids)


class EvidenceError(TallwrightError):
    """The evidence directory could not do its part. When it fails before sending, nothing was sent."""


class ExhibitError(TallwrightError):
    """No exhibit of a record in this evidence directory was handed over, by a link or for an export key.
    Nothing was filed."""


class ExhibitNotReady(ExhibitError):
    """409: the door could not build the exhibit now, and says why — most often that no witness has
    covered the record yet. Nothing was used by asking: a link opens again until it expires, and an
    export key may simply ask again after the next anchor run."""


class LinkSpent(ExhibitError):
    """410: the link was used once already, which is all it was good for. Ask for a new one."""


class ExportKeyRefused(ExhibitError):
    """401: the exhibit door holds no such export key — never issued, replaced by a newer one, or
    withdrawn. Nothing was filed; the backoffice issues a new one."""
