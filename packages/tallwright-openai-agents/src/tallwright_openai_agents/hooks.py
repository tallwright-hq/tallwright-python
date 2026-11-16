# SPDX-License-Identifier: Apache-2.0
"""Cloud Proof for an OpenAI Agents SDK run: the SDK's own run hooks, handed the client you already built.

    from agents import Runner
    from tallwright_cloud import Tallwright
    from tallwright_openai_agents import TallwrightHooks

    client = Tallwright(ingest_url, archive_key, "./tallwright-evidence")
    result = await Runner.run(agent, "Refund ticket 8812", hooks=TallwrightHooks(client))

It decides when to hand the client an event and what content to hand it, and nothing else
(https://docs.tallwright.com/adapters). The commitment, the evidence, sending, sending again and the
receipt are the client's; the projection is :mod:`tallwright_openai_agents.projection`.

- ``on_llm_start``: what the model received (instructions, input items, the tools offered), as context.
- ``on_tool_start``: the tool and its arguments BEFORE it runs, as an action (``action_type`` = the
  tool's name).
- ``on_tool_end``: what the tool returned, as the agent received it, as context. A tool that raised
  returns what the SDK made of the error for the model, and that is what is recorded.
- ``on_handoff``: a handoff to another agent, as an action (``action_type`` = ``handoff``).
- The agent's reasoning or intent is never recorded: reasoning items are left out of the projection, and
  the model's own output is recorded only as the next model call receives it.

**Best effort by default, fail-closed when asked.** By default every event is handed to
``client.asubmit``, which returns once the evidence is safe and sends in the background; a failure is
logged by its type, never with content, and the run goes on. With ``fail_closed=True`` an action is handed
to ``client.acapture`` before the tool runs, and a capture the door did not confirm stops the tool: the
SDK raises it out of ``Runner.run`` wrapped in its ``UserError``. Any other failure raises too.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agents import RunHooks
from tallwright_cloud import Flushed, Tallwright
from tallwright_core.redact import CREDENTIAL_KEYS

from .projection import action_payload, context_payload, handoff_payload, result_payload

LOG = logging.getLogger("tallwright_openai_agents")

#: Gives the client of the Environment a run records into, from that run's context: the object your code
#: passed as ``Runner.run(..., context=...)``.
ClientFor = Callable[[Any], Tallwright]


class TallwrightHooks(RunHooks[Any]):
    """Records an OpenAI Agents SDK run's context and actions into Cloud Proof.

    Hand it ``client``, a :class:`~tallwright_cloud.Tallwright` built by you, or ``client_for``, which gives
    one per run when one process serves many end customers (``Environments.client``). It never builds a
    client and never reads a key. ``actor_authority`` is the role or rule the agent's actions run under,
    never a person; it is set on actions only. ``redact_keys`` names the keys withheld from arguments,
    messages and results, with the path of each recorded. A run takes one ``hooks``: to add your own,
    subclass this and call ``super()`` in each hook you override.
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
        if (client is None) == (client_for is None):
            raise TypeError("hand the hooks a client or a client_for, and not both")
        self._client = client
        self._client_for = client_for
        self._fail_closed = fail_closed
        self._authority = actor_authority
        self._keys = redact_keys
        #: The clients these hooks have handed events to, so ``pending`` and ``flush`` reach each.
        self._used: dict[int, Tallwright] = {} if client is None else {id(client): client}

    def pending(self) -> list[str]:
        """Records handed to a client here and never confirmed or refused (``client.pending()``)."""
        return [name for client in self._used.values() for name in client.pending()]

    def flush(self, timeout: float | None = 30.0) -> list[Flushed]:
        """Wait for what was submitted, client by client (``client.flush()``), at the end of a run."""
        return [client.flush(timeout) for client in self._used.values()]

    def _of(self, context: Any) -> Tallwright:
        if self._client is not None:
            return self._client
        assert self._client_for is not None
        client = self._client_for(getattr(context, "context", None))
        self._used.setdefault(id(client), client)
        return client

    async def _hand(self, context: Any, what: str, build: Callable[[], tuple[Any, str | None]]) -> None:
        try:
            content, action_type = build()
            client = self._of(context)
            if action_type is not None and self._fail_closed:
                await client.acapture(content, action_type=action_type, actor_authority=self._authority)
            elif action_type is not None:
                await client.asubmit(content, action_type=action_type, actor_authority=self._authority)
            else:
                await client.asubmit(content)
        except Exception as failed:  # noqa: BLE001 - best effort must not stop the run, and says so
            if self._fail_closed:
                raise
            LOG.warning("%s was not recorded: %s; the run goes on (best effort)", what, type(failed).__name__)

    async def on_llm_start(self, context: Any, agent: Any, system_prompt: str | None, input_items: list[Any]) -> None:
        await self._hand(context, "the model's context", lambda: (context_payload(agent, system_prompt, input_items, self._keys), None))

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        await self._hand(context, "a tool call", lambda: action_payload(context, agent, tool, self._keys))

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        await self._hand(context, "a tool's result", lambda: (result_payload(context, tool, result, self._keys), None))

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        await self._hand(context, "a handoff", lambda: (handoff_payload(from_agent, to_agent), "handoff"))
