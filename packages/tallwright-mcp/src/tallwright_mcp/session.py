# SPDX-License-Identifier: Apache-2.0
"""Cloud Proof for MCP tool calls, by wrapping the client session you already hold.

    from tallwright_cloud import Tallwright
    from tallwright_mcp import instrument

    client = Tallwright(ingest_url, archive_key, "./tallwright-evidence")
    async with ClientSession(read, write) as session:
        instrument(session, client=client, server="payments")
        await session.call_tool("refund", {"ticket": "8812"})

**Why a wrapper.** Every MCP tool call goes through one object, and rebinding its ``call_tool`` covers
every holder of that session, not only the reference handed in. There is no install order to get right
and no half-instrumented session. It does not import the MCP SDK: it rebinds whatever ``call_tool``
coroutine the object has, so it works across SDK versions and adds nothing to a dependency set.

**What it is entitled to say.** It sees the protocol boundary: the tool's name and the arguments actually
passed, at the moment they are passed, and what came back. It does not see the model decide, and what
the server does behind the tool is outside the record.

It decides when to hand the client a call and what content to hand it, and nothing else
(https://docs.tallwright.com/adapters): the call before it is made, as an action (``mcp:<tool>``), and its
outcome, or the type of what it raised, as context.
"""

from __future__ import annotations

import logging
from typing import Any, TypeVar

from tallwright_cloud import Tallwright
from tallwright_core.redact import CREDENTIAL_KEYS

from .projection import action_type, arguments, failure, outcome

LOG = logging.getLogger("tallwright_mcp")

#: Set on the wrapper, so instrumenting twice is a no-op rather than every call recorded twice.
_MARK = "_tallwright_cloud_instrumented"

S = TypeVar("S")


class NotInstrumentable(TypeError):
    """The object handed in has no ``call_tool`` to wrap.

    Raised rather than handing the object back unchanged: an integrator would believe they were recording,
    and would find out when somebody asked for the evidence.
    """


def instrument(
    session: S,
    *,
    client: Tallwright,
    server: str,
    fail_closed: bool = False,
    actor_authority: str | None = None,
    redact_keys: frozenset[str] = CREDENTIAL_KEYS,
) -> S:
    """Wrap ``session.call_tool`` so every call and its outcome is handed to ``client``; returns ``session``.

    ``client`` is a :class:`~tallwright_cloud.Tallwright` built by you; a vendor with many end customers
    instruments each customer's session with that customer's client. ``server`` names the MCP server, and
    goes in the content. By default each event is handed to ``client.submit`` and a failure is logged by its
    type while the call goes on; with ``fail_closed=True`` the call is handed to ``client.capture`` before it
    is made, and a capture the door did not confirm raises before the tool is called. ``actor_authority``
    names the role or rule the calls run under, never a person. Instrumenting twice changes nothing.
    """
    original = getattr(session, "call_tool", None)
    if original is None:
        raise NotInstrumentable(
            f"{type(session).__name__} has no 'call_tool' to wrap, so nothing would be recorded. "
            "Pass the MCP client session itself, not a wrapper around it."
        )
    if getattr(original, _MARK, False):
        return session

    async def hand(what: str, content: Any, kind: str | None) -> None:
        try:
            if kind is not None and fail_closed:
                await client.acapture(content, action_type=kind, actor_authority=actor_authority)
            elif kind is not None:
                await client.asubmit(content, action_type=kind, actor_authority=actor_authority)
            else:
                await client.asubmit(content)
        except Exception as failed:  # noqa: BLE001 - best effort must not stop the call, and says so
            if fail_closed:
                raise
            LOG.warning("%s was not recorded: %s; the call goes on (best effort)", what, type(failed).__name__)

    async def call_tool(name: str, args: dict[str, Any] | None = None, *more: Any, **kw: Any) -> Any:
        # Handed over BEFORE the call, so a tool that never returns still leaves its request recorded.
        await hand("an MCP tool call", arguments(name, server, args, redact_keys), action_type(name))
        try:
            result = await original(name, args, *more, **kw)
        except BaseException as exc:
            # The failure IS the outcome; it is recorded, then it propagates unchanged.
            await hand("an MCP tool's error", failure(name, server, type(exc).__name__), None)
            raise
        await hand("an MCP tool's result", outcome(name, server, result, redact_keys), None)
        return result

    setattr(call_tool, _MARK, True)
    setattr(session, "call_tool", call_tool)
    return session
