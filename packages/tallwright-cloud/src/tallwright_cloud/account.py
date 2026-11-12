# SPDX-License-Identifier: Apache-2.0
"""An account's Environments, made and kept by the vendor's own system (``/v1/environments``).

    account = Account(app_url, account_key)
    made = account.create("Bäckerei Müller", customer_ref="4711", deployer_label="acme-voice")
    store_secret("4711", made.key.reveal())          # shown once, here and nowhere else

The account key (``ta_…``) is made by an Owner or Admin on the Settings screen and can do what a person
on the Environments screen can: make an Environment, list and find them, replace a recording key,
close one. It is NOT the key an agent records with, and it never belongs in the process that records:
that process holds one recording key per customer and nothing that makes more.

**A create is safe to repeat, and this package always sends one that is.** ``customer_ref`` is
required here, though the API takes a create without one: with it, a create the door already did is
answered 409 with the Environment it made, and nothing is made twice. Without it, an answer lost on
the way back would leave an Environment nobody knows about. What a lost answer still costs is the key,
which is shown once: :class:`EnvironmentExists` says whether an earlier attempt of THIS call may have
made it, and then :meth:`Account.new_key` gives the Environment a key somebody holds.

**Keys come back wrapped.** A recording key in a :class:`Secret`, whose repr shows its face and no
more, so a log line or an error tracker that records the object records no key.
"""

from __future__ import annotations

import http.client
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from . import transport
from .errors import TallwrightError
from .ids import checked_ref

#: The answers that decide nothing: the same request is sent again, after the same waits as a capture.
RETRY = frozenset({408, 425, 429, 500, 502, 503, 504})
DELAYS = (0.5, 1.0, 2.0)
_pause = time.sleep


class AccountError(TallwrightError):
    """The account API refused or could not complete a request, in its own sentence where it gave one."""


class EnvironmentExists(AccountError):
    """409: an open Environment for this ``customer_ref`` exists, and nothing was made."""

    def __init__(self, message: str, environment: Environment, *, maybe_ours: bool) -> None:
        super().__init__(message, status=409)
        self.environment = environment
        #: True when an earlier attempt of the same call may have made it, and its key was lost with
        #: the answer: then ``new_key`` gives it one somebody holds.
        self.maybe_ours = maybe_ours


class Secret:
    """A key shown once. ``reveal`` it into the secret store; nothing else shows more than its face."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = transport.Key(value).reveal()

    def reveal(self) -> str:
        """The key itself, for the one place it is handed to; everything else is shown its first characters."""
        return self._value

    def __repr__(self) -> str:
        return f"Secret({self._value[:11]}…)"


@dataclass(frozen=True)
class Environment:
    """One Environment as the account API shows it."""

    id: str
    name: str
    customer_ref: str | None
    deployer_label: str
    environment_id: str | None
    status: str
    reason: str | None = None
    created_at: str | None = None
    closed_at: str | None = None

    @classmethod
    def read(cls, given: object) -> Environment:
        """An Environment from one entry of the account API's answer; :class:`AccountError` when it is not one."""
        if not isinstance(given, dict) or not isinstance(given.get("id"), str) or not isinstance(given.get("status"), str):
            raise AccountError("the account API answered with something that is not an Environment")
        def text(key: str) -> str | None:
            value = given.get(key)
            return value if isinstance(value, str) else None

        return cls(
            id=given["id"],
            name=text("name") or "",
            customer_ref=text("customer_ref"),
            deployer_label=text("deployer_label") or "",
            environment_id=text("environment_id"),
            status=given["status"],
            reason=text("reason"),
            created_at=text("created_at"),
            closed_at=text("closed_at"),
        )


@dataclass(frozen=True)
class Made:
    """An Environment just made, or given a new key: the key is here once, and nowhere else."""

    environment: Environment
    ingest_url: str
    key: Secret


class Account:
    """The account API of one account, with its account key: it makes, finds, re-keys and closes Environments.

    The account key never belongs in the process that records; that holds one recording key per customer.
    """

    def __init__(self, url: str, account_key: str, *, timeout: float = 90.0) -> None:
        transport.checked_address(url, "the account API")
        self.url = url.rstrip("/")
        self._key = transport.Key(account_key)
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"Account(url={self.url!r}, account_key={self._key!r})"

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any], int]:
        """The status, the JSON body and how many attempts it took; undecided answers are tried again."""
        # A POST without a body still says so: Content-Length 0, which no proxy has to guess at.
        data = (b"" if method == "POST" else None) if body is None else json.dumps(body).encode("utf-8")
        kind = None if body is None else "application/json"
        last = ""
        attempts = 0
        for wait in (0.0, *DELAYS):
            if wait:
                _pause(wait)
            attempts += 1
            try:
                status, raw, _ = transport.exchange(
                    method, self.url + path, self._key, data, kind, self._timeout, transport.MAX_ANSWER
                )
            except (OSError, http.client.HTTPException) as failed:
                last = f"{type(failed).__name__}: {getattr(failed, 'reason', failed)}"
                continue
            # Read as the door's answers are: an answer nested past any stack is no answer, not a crash.
            answer = transport.object_in(raw) or {}
            if status in RETRY:
                last = f"it answered {status} ({answer.get('error') or 'no sentence'})"
                continue
            return status, answer, attempts
        raise AccountError(f"{method} {path}: {attempts} attempts, the last: {last}. Nothing is known to have been done")

    def _refused(self, method: str, path: str, status: int, answer: dict[str, Any]) -> AccountError:
        said = answer.get("error")
        return AccountError(f"{method} {path}: {status} ({said if isinstance(said, str) else 'without the API sentence'})", status=status)

    def create(self, name: str, *, customer_ref: str, deployer_label: str) -> Made:
        """Make an Environment for one end customer; its key is in the answer, once.

        ``customer_ref`` is the one :class:`~tallwright_cloud.environments.Environments` keeps the
        customer's evidence beneath, so it is held to the same rule (``ids.checked_ref``) here, and a
        ref nothing could record under is refused before anything is made.
        """
        if not isinstance(customer_ref, str) or not customer_ref.strip():
            raise ValueError("customer_ref is required: it is what makes a repeated create safe")
        checked_ref(customer_ref)
        body = {"name": name, "customer_ref": customer_ref, "deployer_label": deployer_label}
        status, answer, attempts = self._call("POST", "/v1/environments", body)
        if status == 409 and "environment" in answer:
            existing = Environment.read(answer["environment"])
            raise EnvironmentExists(
                f"an Environment for customer_ref {customer_ref!r} exists already ({existing.status}); "
                "nothing was made"
                + (
                    ". An earlier attempt of this call may have made it and lost the answer, and with it "
                    "the key: new_key(...) gives it a key you then hold"
                    if attempts > 1
                    else ""
                ),
                existing,
                maybe_ours=attempts > 1,
            )
        if status != 201:
            raise self._refused("POST", "/v1/environments", status, answer)
        return self._made(answer)

    def _made(self, answer: dict[str, Any]) -> Made:
        key, ingest = answer.get("key"), answer.get("ingest_url")
        if not isinstance(key, str) or not isinstance(ingest, str):
            raise AccountError("the account API answered without the key or the ingest address")
        environment = answer.get("environment") or {}
        if isinstance(environment, dict) and "status" not in environment:
            environment = {**environment, "status": "live"}
        return Made(Environment.read(environment), ingest, Secret(key))

    def environments(self, *, status: str | None = None, customer_ref: str | None = None) -> Iterator[Environment]:
        """Every Environment of the account, page by page, in the order the API keeps them.

        A page goes on only to an offset past its own: a ``next_offset`` that repeats it, goes back or is
        no number is an :class:`AccountError`, never a loop that asks forever or a listing cut short.
        """
        offset = 0
        while True:
            query: dict[str, str] = {"limit": "200", "offset": str(offset)}
            if status is not None:
                query["status"] = status
            if customer_ref is not None:
                query["customer_ref"] = customer_ref
            path = "/v1/environments?" + urlencode(query)
            code, answer, _ = self._call("GET", path)
            if code != 200:
                raise self._refused("GET", "/v1/environments", code, answer)
            for given in answer.get("environments") or []:
                yield Environment.read(given)
            following = answer.get("next_offset")
            if following is None:
                return
            if not isinstance(following, int) or isinstance(following, bool) or following <= offset:
                raise AccountError(
                    f"GET /v1/environments: the API answered next_offset {repr(following)[:40]} to offset "
                    f"{offset}, which does not move forward, so the listing stops here instead of asking again"
                )
            offset = following

    def find(self, customer_ref: str) -> Environment | None:
        """The open Environment of ``customer_ref``, or None."""
        for found in self.environments(customer_ref=customer_ref):
            if found.status != "closed":
                return found
        return None

    def new_key(self, environment: str) -> Made:
        """Replace an Environment's recording key: the old one stops at once, the new one is here once."""
        path = f"/v1/environments/{quote(environment, safe='')}/key"
        status, answer, _ = self._call("POST", path)
        if status != 200:
            raise self._refused("POST", path, status, answer)
        return self._made(answer)

    def close(self, environment: str) -> Environment:
        """Close an Environment when its customer leaves. Its log stays and still exports."""
        path = f"/v1/environments/{quote(environment, safe='')}/close"
        status, answer, _ = self._call("POST", path)
        if status != 200:
            raise self._refused("POST", path, status, answer)
        return Environment.read(answer.get("environment") or {})
