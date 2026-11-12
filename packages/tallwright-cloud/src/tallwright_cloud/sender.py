# SPDX-License-Identifier: Apache-2.0
"""Sending in the background: the agent waits for its evidence to be safe, never for the network.

``Tallwright.submit`` commits the content and writes the pair and the line (``evidence.py``), and
returns. From there one thread per :class:`Sender` delivers what is queued: in the order it was
submitted, several lines to a request, the same bytes again for as long as the door's answer decides
nothing. A process that ends before its queue is empty loses nothing either: what was not confirmed is
pending in the evidence, and the next client to start on it sends it again.

**What it never does.** It never commits anything, never builds a line and never reads an answer: the
client does all three (``client.py``), for one line or for many, so there is one reading of the door
and not two. It never drops a record. A record leaves the queue confirmed, refused by the door, or
because its client was stopped, and in the last case it is still pending in the evidence.

**When to stop.** A key the door does not hold (401), a closed account (403) or a redirect to an
address nobody configured end sending for that client: retrying cannot change any of them, and every
further record stays pending until a person acts. :meth:`Sender.resume` lifts the stop, once the key
or the account is right again. Everything else that decides nothing — no answer, a busy door, a 5xx —
is tried again later, waiting longer each time up to a minute, while the other clients of the same
sender carry on.

**One thread for many Environments.** ``Environments`` gives all its clients one sender, so a vendor
with a thousand end customers has one thread, not a thousand. Each client is backed off on its own,
and the clients take turns: one that always has a record waiting holds up none of the others.

**Told, not silent.** Every problem goes to the client's ``on_problem`` if it has one, and to the
``tallwright_cloud`` logger in any case, by type and record name, never with content.
"""

from __future__ import annotations

import atexit
import logging
import os
import random
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .errors import TallwrightError

if TYPE_CHECKING:  # pragma: no cover
    from .client import Tallwright

log = logging.getLogger("tallwright_cloud")

#: The first wait after an answer that decided nothing, and the longest one.
FIRST_WAIT = 0.5
LONGEST_WAIT = 60.0
#: How many lines go to the door in one request, and how many bytes at most (the door takes 4 MiB).
BATCH_LINES = 100
BATCH_BYTES = 1 << 20

#: The wait a test replaces rather than sleeping.
_clock = time.monotonic


@dataclass(frozen=True)
class Flushed:
    """What a flush left: how many records are still to be sent, and the clients that were stopped."""

    pending: int
    stopped: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """Whether nothing is left to send and no client was stopped."""
        return self.pending == 0 and not self.stopped


@dataclass
class _Lane:
    """One client's queue in a sender."""

    client: Tallwright
    queue: deque[str]
    not_before: float = 0.0
    wait: float = 0.0
    stopped: str | None = None
    #: How many of its records are with the door right now.
    inflight: int = 0


class Sender:
    """One thread delivering the queued records of one or more clients. See the module docstring."""

    def __init__(self, *, batch_lines: int = BATCH_LINES, batch_bytes: int = BATCH_BYTES) -> None:
        self.batch_lines = batch_lines
        self.batch_bytes = batch_bytes
        self._lock = threading.Condition()
        self._lanes: dict[int, _Lane] = {}
        self._closed = False
        self._thread: threading.Thread | None = None
        self._pid = os.getpid()
        _live.add(self)

    def _forked(self) -> None:
        """A child of a fork starts empty: its parent's queue is its parent's, and so is its thread.

        Every entry calls this before it takes the lock: a parent's thread that held the lock at the
        fork does not exist in the child, and the child's copy of the lock would never be let go of.
        """
        if self._pid != os.getpid():
            self._lock = threading.Condition()
            self._lanes, self._thread, self._pid = {}, None, os.getpid()

    def _ensure(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, name="tallwright-sender", daemon=True)
            self._thread.start()

    def put(self, client: Tallwright, record_ids: list[str]) -> None:
        """Queue ``client``'s records, in the order they were submitted; a stopped client takes none."""
        self._forked()
        with self._lock:
            if self._closed:
                newest = record_ids[-1]
                raise TallwrightError(
                    f"{newest}: its evidence is kept and it is pending, and the sender of this client was "
                    "closed, so it is not sent from here. A new client on the same evidence sends it",
                    record_id=newest,
                )
            self._ensure()
            lane = self._lanes.setdefault(id(client), _Lane(client, deque()))
            if lane.stopped is None:
                known = set(lane.queue)
                lane.queue.extend(name for name in record_ids if name not in known)
            self._lock.notify_all()

    def resume(self, client: Tallwright) -> None:
        """Lift ``client``'s stop and its backoff: a person's act, once its key or its account is right."""
        self._forked()
        with self._lock:
            lane = self._lanes.get(id(client))
            if lane is not None:
                lane.stopped, lane.wait, lane.not_before = None, 0.0, 0.0
                self._lock.notify_all()

    def queued(self, client: Tallwright) -> int:
        self._forked()
        with self._lock:
            lane = self._lanes.get(id(client))
            return len(lane.queue) + lane.inflight if lane else 0

    def stopped(self, client: Tallwright) -> str | None:
        self._forked()
        with self._lock:
            lane = self._lanes.get(id(client))
            return lane.stopped if lane else None

    def flush(self, timeout: float | None = None, client: Tallwright | None = None) -> Flushed:
        """Wait until everything queued (for ``client``, or for all) is confirmed, refused or stopped.

        Once the sender is closed no thread is left to send anything: what is left is said at once.
        """
        self._forked()
        deadline = None if timeout is None else _clock() + timeout
        with self._lock:
            while True:
                lanes = [lane for key, lane in self._lanes.items() if client is None or key == id(client)]
                left = sum(len(lane.queue) + lane.inflight for lane in lanes if lane.stopped is None)
                if left == 0 or self._closed:
                    break
                remaining = None if deadline is None else deadline - _clock()
                if remaining is not None and remaining <= 0:
                    break
                self._lock.wait(remaining if remaining is not None else 1.0)
            stopped = tuple(sorted(lane.stopped for lane in lanes if lane.stopped))
            return Flushed(left, stopped)

    def close(self, timeout: float | None = 10.0) -> Flushed:
        """Flush for up to ``timeout``, then end the thread: once this returns, nothing more is sent."""
        flushed = self.flush(timeout)
        with self._lock:
            self._closed = True
            self._lock.notify_all()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            # A request already with the door is answered and read; nothing new starts.
            thread.join()
        return flushed

    # --- the thread --------------------------------------------------------------------------------

    def _next(self) -> tuple[_Lane, list[str]] | None:
        """The lane whose turn it is, and its next batch; None when nothing may be sent now.

        The lanes take turns. They are kept in the order they were last served, the one served now goes
        to the back, and the first that may send is served: a client with a record waiting at every turn
        holds up no other, and one whose wait is over is served at its next turn.
        """
        now = _clock()
        lane = next(
            (lane for lane in self._lanes.values() if lane.queue and lane.stopped is None and lane.not_before <= now),
            None,
        )
        if lane is None:
            return None
        self._lanes[id(lane.client)] = self._lanes.pop(id(lane.client))
        batch: list[str] = []
        while lane.queue and len(batch) < self.batch_lines:
            batch.append(lane.queue.popleft())
        return lane, batch

    def _sleep_for(self) -> float | None:
        waiting = [lane.not_before for lane in self._lanes.values() if lane.queue and lane.stopped is None]
        if not waiting:
            return None
        return max(0.0, min(waiting) - _clock())

    def _run(self) -> None:
        while True:
            with self._lock:
                picked = None if self._closed else self._next()
                while picked is None:
                    if self._closed:
                        # What is still queued stays pending in the evidence, for the next client.
                        return
                    self._lock.wait(self._sleep_for())
                    picked = self._next()
                lane, batch = picked
                lane.inflight = len(batch)
            try:
                again, stop = lane.client._deliver_batch(batch, self.batch_bytes)
            except Exception as failed:  # noqa: BLE001 - the thread outlives any one batch
                log.exception("tallwright_cloud: a batch of %d record(s) failed unexpectedly; it is sent again", len(batch))
                again, stop = batch, None
                del failed
            with self._lock:
                lane.inflight = 0
                if stop is not None:
                    lane.stopped = stop
                    lane.queue.clear()
                elif again:
                    lane.queue.extendleft(reversed(again))
                    lane.wait = FIRST_WAIT if not lane.wait else min(lane.wait * 2, LONGEST_WAIT)
                    lane.not_before = _clock() + lane.wait * random.uniform(0.8, 1.2)  # noqa: S311 - jitter
                else:
                    lane.wait = 0.0
                    lane.not_before = 0.0
                self._lock.notify_all()


#: Every sender alive in this process, so that an ending interpreter gives each a moment to deliver.
_live: weakref.WeakSet[Sender] = weakref.WeakSet()


@atexit.register
def _deliver_before_exit() -> None:  # pragma: no cover - runs when the interpreter ends
    for sender in list(_live):
        try:
            sender.flush(timeout=5.0)
        except Exception:  # noqa: BLE001 - nothing may stop the interpreter ending
            pass
