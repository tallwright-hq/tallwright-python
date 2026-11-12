# SPDX-License-Identifier: Apache-2.0
"""How a record is named, and what the names can show about records that never arrived.

**A minted name counts.** Without a ``record_id`` of the caller's own, a record is named
``<session>.<number>``: sixteen random hex digits for this client instance, and a number that counts up
from 000001 inside it. The name is inside the record and therefore inside its hash, so the sequence is
sealed with the records and travels in every exhibit.

**One session per process.** A process that forks after making a client (a pre-forking web server, a
worker pool) would otherwise hand every child the same session and the same count, and the children
would mint the same names. A child notices it is one by its process id and draws a session of its own.
Sixty-four random bits keep sessions apart across millions of clients.

**What a sequence shows.** A number missing below the highest one a session reached is a capture that
was numbered and is not in the log: one that failed before or during its send and was never resent, or
one somebody left out on purpose and would now have to explain. :func:`gaps` lists them.

**What it cannot show, stated rather than discovered.** A missing TAIL (the last records of a session
never sent), a session that sent nothing at all, and every action the agent took without calling
``capture``. A sequence makes a hole in what was captured visible; it says nothing about what was
never captured, which is the residual this product states most loudly. It is a
signal for a reader, never a proof that a log is complete.

**A name of the caller's own** is taken as it is, provided it can name a folder of its own on every
system the evidence may live on: the exhibit door's own rule for a record id it uses as a folder name
(``[A-Za-z0-9._-]{1,100}``), in lower case, starting with a letter or digit, not ending in a dot, and
not a name Windows reserves for a device. Lower case, because Windows and macOS take two names that
differ only in case for one folder: on them ``Order-7`` and ``order-7`` would be one record's folder,
and ``Acme-1`` and ``acme-1`` one customer's, where Linux and a bucket keep them apart. It carries no
sequence. It also travels in the clear and is sealed into every exhibit, so it must name an event,
never a person; a name refused is refused by the rule it breaks and never repeated, since what is
refused is most often a person's name or address. A ``customer_ref`` is held to the same rule
(:func:`checked_ref`).
"""

from __future__ import annotations

import os
import re
import secrets
import threading
from collections.abc import Iterable

#: Device names Windows will not create a folder under, with or without an extension.
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{n}" for n in range(10)), *(f"LPT{n}" for n in range(10))}
)
#: A name this client minted: the session, a dot, and the count.
_MINTED = re.compile(r"([0-9a-f]{16})\.([0-9]{6,})")
#: What every name that becomes a folder is, said once for every refusal.
_RULE = (
    "1 to 100 of a-z 0-9 . _ -, starting with a letter or digit, not ending in a dot, and not a device "
    "name Windows reserves"
)


def _broken(name: str) -> str | None:
    """The rule of a folder name that ``name`` breaks, in words that do not repeat it; None when it keeps them all.

    This is the rule, not a description of one kept elsewhere: a name is taken exactly when this is None.
    """
    if not name:
        return "it is empty"
    if len(name) > 100:
        return f"it is {len(name)} characters long"
    if re.search(r"[A-Z]", name):
        return (
            "it has an upper-case letter, and Windows and macOS take two names that differ only in case "
            "for one folder"
        )
    if re.search(r"[^a-z0-9._-]", name):
        return "it has a character other than a-z 0-9 . _ -"
    if name[0] in "._-":
        return "it does not start with a letter or a digit"
    if name.endswith("."):
        return "it ends in a dot, which Windows drops"
    if name.split(".", 1)[0].upper() in _RESERVED:
        return "it is a device name Windows reserves"
    return None


def checked_record_id(record_id: object) -> str:
    """A caller's ``record_id``, if it can name a folder of its own everywhere; refused by the rule it breaks otherwise."""
    if not isinstance(record_id, str):
        raise TypeError(f"record_id is text, not {type(record_id).__name__}")
    if why := _broken(record_id):
        raise ValueError(
            f"record_id cannot name a folder on every system: {why}. A record_id is {_RULE}. It travels in "
            "the clear and is sealed into every exhibit, so name the event, never a person; the one "
            "refused is not repeated here"
        )
    return record_id


def checked_ref(customer_ref: object) -> str:
    """A ``customer_ref`` that can name a folder of its own everywhere; refused by the rule it breaks otherwise.

    It names the folder one end customer's evidence lives in, beneath the store of
    :class:`~tallwright_cloud.environments.Environments`, so the rule is a record_id's: two refs a
    vendor can use are two folders on every system, and one customer's content and salts can never
    sit in another's. :meth:`~tallwright_cloud.account.Account.create` holds a ref to it before it
    makes anything.
    """
    if not isinstance(customer_ref, str):
        raise TypeError(f"customer_ref is text, not {type(customer_ref).__name__}")
    if why := _broken(customer_ref):
        raise ValueError(
            f"customer_ref cannot name a folder on every system: {why}. A customer_ref is {_RULE}. Use "
            "your own customer number, never a person's name or address; the one refused is not "
            "repeated here"
        )
    return customer_ref


class Minter:
    """``<session>.<number>`` for every capture of one client in one process, without a hole or a repeat."""

    def __init__(self) -> None:
        self._begin()

    def _begin(self) -> None:
        # A new lock too: a parent's thread that held the old one at the fork does not exist here.
        self._lock = threading.Lock()
        self._pid = os.getpid()
        self.session = secrets.token_hex(8)
        self._count = 0

    def next(self) -> str:
        if os.getpid() != self._pid:
            self._begin()
        with self._lock:
            self._count += 1
            return f"{self.session}.{self._count:06d}"


def gaps(record_ids: Iterable[str]) -> dict[str, list[int]]:
    """For every session among these names, the numbers missing below the highest one seen.

    Names this client did not mint are passed over. An empty list means no hole below the highest
    number, not that nothing is missing: see the module docstring for what no sequence can show.
    """
    seen: dict[str, set[int]] = {}
    for name in record_ids:
        minted = _MINTED.fullmatch(name)
        if minted:
            seen.setdefault(minted.group(1), set()).add(int(minted.group(2)))
    return {session: sorted(set(range(1, max(numbers) + 1)) - numbers) for session, numbers in seen.items()}
