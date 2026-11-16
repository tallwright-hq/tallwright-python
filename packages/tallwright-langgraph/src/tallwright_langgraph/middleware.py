# SPDX-License-Identifier: Apache-2.0
"""Cloud Proof for a LangChain/LangGraph v1 agent: one middleware, handed the client you already built.

    from tallwright_cloud import Tallwright
    from tallwright_langgraph import TallwrightMiddleware

    client = Tallwright(ingest_url, archive_key, "./tallwright-evidence")
    agent = create_agent(model, tools, middleware=[TallwrightMiddleware(client)])

It decides when to hand the client an event and what content to hand it, and nothing else
(https://docs.tallwright.com/adapters). The commitment, the evidence, sending, sending again and the
receipt are the client's; the projection is :mod:`tallwright_langgraph.projection`.

- ``wrap_model_call``: what the model received, as context (``CONTEXT_RECEIVED``).
- ``wrap_tool_call``: the tool and its arguments BEFORE it runs, as an action (``ACTION_TRIGGERED``,
  ``action_type`` = the tool's name); then what it returned, or the type of what it raised, as context.
- The agent's reasoning or intent is never recorded: LangChain has no hook for intent, and a
  provider's reasoning blocks are left out of the projection.

**Best effort by default, fail-closed when asked.** By default every event is handed to
``client.submit``, which returns once the evidence is safe and sends in the background, so the agent
never waits on the network; a failure is logged by its type, never with content, and the agent keeps
serving. With ``fail_closed=True`` an action is handed to ``client.capture`` before the tool runs, and a
capture the door did not confirm raises before the tool runs; any other failure raises too.

**Install it LAST in** ``middleware=[...]``. LangChain composes middleware outermost first, and this one
records the tool call before calling the handler. A middleware listed after it runs inside it and may
rewrite the call afterwards (context editing, PII, summarization, tool selection, human-in-the-loop), and
the record would describe the call as it was before that rewrite. No middleware can see what an inner
one does, so this is a requirement on the deployment that the library cannot enforce.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware, ModelRequest, ModelResponse, ToolCallRequest
from tallwright_cloud import Flushed, Tallwright
from tallwright_core.redact import CREDENTIAL_KEYS

from .projection import action_payload, error_payload, model_payload, result_payload

LOG = logging.getLogger("tallwright_langgraph")

#: Gives the client of the Environment a run records into, from that run's LangGraph ``runtime``: its
#: ``context`` is what your code passed as ``invoke(..., context=...)``.
ClientFor = Callable[[Any], Tallwright]


class TallwrightMiddleware(AgentMiddleware):  # type: ignore[misc]  # AgentMiddleware is untyped
    """Records a LangChain/LangGraph v1 agent's context and actions into Cloud Proof.

    Hand it ``client``, a :class:`~tallwright_cloud.Tallwright` built by you, or ``client_for``, which
    gives one per run when one agent process serves many end customers (``Environments.client``). It
    never builds a client and never reads a key: the key and where evidence lives are yours.

    ``actor_authority`` is the role or rule the agent's actions run under (``role:payments-agent``), never
    a person; it is set on actions only. ``redact_keys`` names the keys whose values are withheld from
    tool arguments, messages and results, with the path of each recorded.
    """

    def __init__(
        self,
        client: Tallwright | None = None,
        *,
        client_for: ClientFor | None = None,
        fail_closed: bool = False,
        actor_authority: str | None = None,
        redact_keys: frozenset[str] = CREDENTIAL_KEYS,
    ) -> None:
        super().__init__()
        if (client is None) == (client_for is None):
            raise TypeError("hand the middleware a client or a client_for, and not both")
        self._client = client
        self._client_for = client_for
        self._fail_closed = fail_closed
        self._authority = actor_authority
        self._keys = redact_keys
        #: The clients this middleware has handed events to, so ``pending`` and ``flush`` reach each.
        self._used: dict[int, Tallwright] = {} if client is None else {id(client): client}

    # -- what the adapter adds to the client's surface ---------------------------------------

    def pending(self) -> list[str]:
        """Records handed to a client here and never confirmed or refused (``client.pending()``)."""
        return [name for client in self._used.values() for name in client.pending()]

    def flush(self, timeout: float | None = 30.0) -> list[Flushed]:
        """Wait for what was submitted, client by client (``client.flush()``), at the end of a run."""
        return [client.flush(timeout) for client in self._used.values()]

    # -- one event ------------------------------------------------------------------------------

    def _of(self, runtime: Any) -> Tallwright:
        if self._client is not None:
            return self._client
        assert self._client_for is not None
        client = self._client_for(runtime)
        self._used.setdefault(id(client), client)
        return client

    def _failed(self, what: str, failed: Exception, *, stops: bool) -> None:
        """A capture that failed: raised when it must stop the agent, logged by its type otherwise."""
        if stops:
            raise failed
        LOG.warning("%s was not recorded: %s; the agent goes on (best effort)", what, type(failed).__name__)

    def _record(self, runtime: Any, what: str, build: Callable[[], tuple[Any, str | None]]) -> None:
        try:
            content, action_type = build()
            client = self._of(runtime)
            if action_type is not None and self._fail_closed:
                client.capture(content, action_type=action_type, actor_authority=self._authority)
            elif action_type is not None:
                client.submit(content, action_type=action_type, actor_authority=self._authority)
            else:
                client.submit(content)
        except Exception as failed:  # noqa: BLE001 - best effort must not stop the agent, and says so
            self._failed(what, failed, stops=self._fail_closed)

    async def _arecord(self, runtime: Any, what: str, build: Callable[[], tuple[Any, str | None]]) -> None:
        try:
            content, action_type = build()
            client = self._of(runtime)
            if action_type is not None and self._fail_closed:
                await client.acapture(content, action_type=action_type, actor_authority=self._authority)
            elif action_type is not None:
                await client.asubmit(content, action_type=action_type, actor_authority=self._authority)
            else:
                await client.asubmit(content)
        except Exception as failed:  # noqa: BLE001 - best effort must not stop the agent, and says so
            self._failed(what, failed, stops=self._fail_closed)

    # -- the hooks ----------------------------------------------------------------------------

    def wrap_model_call(self, request: ModelRequest, handler: Callable[[ModelRequest], ModelResponse]) -> ModelResponse:
        self._record(request.runtime, "the model's context", lambda: (model_payload(request, self._keys), None))
        return handler(request)

    def wrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], Any]) -> Any:
        self._record(request.runtime, "a tool call", lambda: action_payload(request, self._keys))
        try:
            result = handler(request)
        except Exception as exc:
            kind = type(exc).__name__
            self._record(request.runtime, "a tool's error", lambda: (error_payload(request, kind), None))
            raise
        self._record(request.runtime, "a tool's result", lambda: (result_payload(request, result, self._keys), None))
        return result

    async def awrap_model_call(
        self, request: ModelRequest, handler: Callable[[ModelRequest], Awaitable[ModelResponse]]
    ) -> ModelResponse:
        await self._arecord(request.runtime, "the model's context", lambda: (model_payload(request, self._keys), None))
        return await handler(request)

    async def awrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], Awaitable[Any]]) -> Any:
        await self._arecord(request.runtime, "a tool call", lambda: action_payload(request, self._keys))
        try:
            result = await handler(request)
        except Exception as exc:
            kind = type(exc).__name__
            await self._arecord(request.runtime, "a tool's error", lambda: (error_payload(request, kind), None))
            raise
        await self._arecord(
            request.runtime, "a tool's result", lambda: (result_payload(request, result, self._keys), None)
        )
        return result
