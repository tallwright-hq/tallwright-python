# SPDX-License-Identifier: Apache-2.0
"""Many end customers from one process: one Environment each, kept apart by construction.

A vendor whose agent serves many end customers records each customer's events in that customer's
own Environment, under that Environment's own key, so that a customer's evidence is kept,
countersigned and handed over apart from everybody else's::

    environments = Environments(ingest_url, key_for, S3Evidence(s3, "acme-evidence"))
    environments.client("customer-4711").submit(content, action_type="appointment.booked")

``key_for(customer_ref)`` is the vendor's: it reads the key from wherever the vendor keeps one per
customer (a secret store, a vault), and this package never sees a key it was not handed for one
customer. Each customer's evidence lives beneath its own ``customer_ref`` in the store, so one
customer's records can never be sent again under another customer's key: the directory a client
reads is the one its customer owns. A ``customer_ref`` is lower case (``ids.checked_ref``), so two
customers are two folders on Windows and macOS too, where a name and its other-case spelling are
one. All the clients share one sending thread (``sender.py``).

What stays the vendor's to get right, stated rather than discovered: that ``key_for`` returns the key
of the Environment made FOR that customer. Nothing on this side can tell two customers' keys apart
before the door answers, and the door answers only for the key it was sent.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from types import TracebackType
from typing import Self

from .client import Problem, Tallwright
from .errors import EvidenceError
from .ids import checked_ref
from .sender import Flushed, Sender
from .store import EvidenceStore, store_of


class Environments:
    """One :class:`Tallwright` per end customer, made on first use, sharing one sender.

    ``url`` is the account's ingest address (the same for all its Environments), ``key_for`` returns a
    customer's recording key, ``evidence`` is the store all customers' evidence lives in, each beneath
    its ``customer_ref``.
    """

    def __init__(
        self,
        url: str,
        key_for: Callable[[str], str],
        evidence: str | os.PathLike[str] | EvidenceStore,
        *,
        timeout: float = 30.0,
        on_problem: Problem | None = None,
    ) -> None:
        self.url = url
        self._key_for = key_for
        try:
            self._store = store_of(evidence)
        except OSError as failed:
            raise EvidenceError(
                f"the evidence {str(evidence)!r} cannot be used ({failed.strerror or failed}). "
                "Nothing was sent: without it, a salt would exist only in memory"
            ) from None
        self._timeout = timeout
        self._on_problem = on_problem
        self._sender = Sender()
        self._clients: dict[str, Tallwright] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"Environments(url={self.url!r}, evidence={self._store!r}, clients={len(self._clients)})"

    def __enter__(self) -> Self:
        return self

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None, trace: TracebackType | None) -> None:
        self.close()

    def client(self, customer_ref: str) -> Tallwright:
        """The client of ``customer_ref``'s Environment, with its evidence beneath ``customer_ref``."""
        ref = checked_ref(customer_ref)
        with self._lock:
            made = self._clients.get(ref)
            if made is None:
                try:
                    store = self._store.within(ref)
                except OSError as failed:
                    raise EvidenceError(
                        f"{ref}: its evidence cannot be used ({failed.strerror or failed}). Nothing was sent"
                    ) from None
                made = Tallwright(
                    self.url,
                    self._key_for(ref),
                    store,
                    timeout=self._timeout,
                    on_problem=self._on_problem,
                    sender=self._sender,
                )
                self._clients[ref] = made
            return made

    def forget(self, customer_ref: str) -> None:
        """Drop a customer's client, after its key was replaced: the next ``client`` asks ``key_for`` again."""
        with self._lock:
            self._clients.pop(checked_ref(customer_ref), None)

    def flush(self, timeout: float | None = 30.0) -> Flushed:
        """Wait up to ``timeout`` seconds for what every customer's client submitted; what is still to be sent."""
        return self._sender.flush(timeout)

    def close(self, timeout: float | None = 10.0) -> Flushed:
        """Flush, and end the one sending thread every customer's client shares. What is left stays pending."""
        for made in list(self._clients.values()):
            made._closed = True
        return self._sender.close(timeout)
