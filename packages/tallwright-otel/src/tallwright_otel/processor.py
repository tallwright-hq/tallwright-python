# SPDX-License-Identifier: Apache-2.0
"""Cloud Proof from OpenTelemetry: a span processor that hands a client the GenAI spans your tracing has.

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON
    from tallwright_cloud import Tallwright
    from tallwright_otel import install

    provider = TracerProvider(sampler=ALWAYS_ON)
    install(provider, Tallwright(ingest_url, archive_key, "./tallwright-evidence"))

Any instrumentation that follows the OpenTelemetry semantic conventions for generative AI feeds it. It
decides when to hand the client an event and what content to hand it, and nothing else
(https://docs.tallwright.com/adapters):

- an ``execute_tool`` span: the tool and its arguments as an action (``action_type`` = the tool's name),
  then what it returned, or the type of its error, as context;
- a ``chat``, ``text_completion`` or ``generate_content`` span: what the model received, as context.

Each record carries the moment the span gives (``timestamp``), and its content names the trace and the
span, so a record and the trace it came from can be found from each other.

**What it cannot do, by construction.** A span reaches a processor when it ENDS, after the tool ran, so
this adapter records an action afterwards and can never stop one: it offers no fail-closed mode, and a
deployment that must not act unrecorded uses a framework adapter instead. A span that was not sampled
never reaches any processor, so :func:`install` refuses a provider whose sampler can drop one; sample in
your collector instead. Arguments, results and messages are opt-in in the conventions: what a span did
not carry is named in ``absent``, never guessed.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from tallwright_cloud import Tallwright
from tallwright_core.redact import CREDENTIAL_KEYS, scrub

LOG = logging.getLogger("tallwright_otel")

#: The operations whose spans carry what a model received.
INFERENCE = frozenset({"chat", "text_completion", "generate_content"})

#: The message parts committed to (the conventions' part types). A ``reasoning`` part, or a type that does
#: not exist yet, is replaced by a marker and named in ``omitted_parts``.
PART_TYPES = frozenset({"text", "tool_call", "tool_call_response", "blob", "file", "uri"})
OMITTED = "[omitted: not a recorded message-part type]"


class SamplerDropsSpans(ValueError):
    """The provider's sampler can drop a span, and a dropped span would be an action nobody recorded."""


def _when(nanoseconds: int | None) -> str | None:
    if nanoseconds is None:
        return None
    return datetime.fromtimestamp(nanoseconds / 1e9, tz=timezone.utc).isoformat()


def _value(raw: Any) -> Any:
    """An attribute value: the JSON it spells when it is JSON text (Python spans carry strings), else itself."""
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    if isinstance(raw, tuple):
        return list(raw)
    return raw


def _parts(messages: Any, path: str) -> tuple[Any, list[str]]:
    """Messages with every part of an unrecorded type replaced by a marker; the paths replaced."""
    omitted: list[str] = []
    if not isinstance(messages, list):
        return messages, omitted
    out = []
    for i, message in enumerate(messages):
        if isinstance(message, dict) and isinstance(message.get("parts"), list):
            parts = []
            for j, part in enumerate(message["parts"]):
                kind = part.get("type") if isinstance(part, dict) else None
                if kind in PART_TYPES:
                    parts.append(part)
                else:
                    parts.append({"type": kind, "omitted": OMITTED})
                    omitted.append(f"{path}[{i}].parts[{j}].{kind}")
            message = {**message, "parts": parts}
        out.append(message)
    return out, omitted


class TallwrightSpanProcessor(SpanProcessor):
    """Hands a :class:`~tallwright_cloud.Tallwright` client the GenAI spans that end. Best effort only.

    Use :func:`install`, which refuses a sampler that can drop a span. Each event goes to
    ``client.submit``; a failure is logged by its type, never with content, and the span goes on to every
    other processor. ``actor_authority`` names the role or rule the actions run under, never a person.
    """

    def __init__(
        self, client: Tallwright, *, actor_authority: str | None = None, redact_keys: frozenset[str] = CREDENTIAL_KEYS
    ) -> None:
        self._client = client
        self._authority = actor_authority
        self._keys = redact_keys

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Nothing: the attributes an event is made of are set while the span runs."""

    def on_end(self, span: ReadableSpan) -> None:
        attributes = dict(span.attributes or {})
        operation = attributes.get("gen_ai.operation.name")
        try:
            if operation == "execute_tool":
                self._tool(span, attributes)
            elif operation in INFERENCE:
                self._inference(span, attributes)
        except Exception as failed:  # noqa: BLE001 - best effort must not break the tracing pipeline
            LOG.warning("a %s span was not recorded: %s (best effort)", operation, type(failed).__name__)

    def shutdown(self) -> None:
        """Nothing of its own: the client's sending is the client's."""

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Waits for what was submitted (``client.flush``); whether nothing is left to send."""
        return self._client.flush(timeout_millis / 1000).complete

    # -- the two kinds of span ------------------------------------------------------------------

    def _where(self, span: ReadableSpan) -> dict[str, str | None]:
        context = span.get_span_context()
        if context is None:
            return {"trace_id": None, "span_id": None}
        return {"trace_id": format(context.trace_id, "032x"), "span_id": format(context.span_id, "016x")}

    def _tool(self, span: ReadableSpan, attributes: dict[str, Any]) -> None:
        name = str(attributes.get("gen_ai.tool.name") or span.name)
        call = attributes.get("gen_ai.tool.call.id")
        absent = [a for a in ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result") if a not in attributes]
        args, withheld = scrub(_value(attributes.get("gen_ai.tool.call.arguments")), self._keys)
        self._client.submit(
            {
                "tool": name,
                "tool_call_id": call,
                "tool_type": attributes.get("gen_ai.tool.type"),
                "arguments": args,
                "withheld_argument_keys": sorted(set(withheld)),
                "absent": [a for a in absent if a.endswith("arguments")],
                "span": self._where(span),
            },
            action_type=name,
            actor_authority=self._authority,
            timestamp=_when(span.start_time),
        )
        error = attributes.get("error.type")
        if error is not None:
            outcome: dict[str, Any] = {"tool": name, "tool_call_id": call, "error": str(error)}
        else:
            result, taken = scrub(_value(attributes.get("gen_ai.tool.call.result")), self._keys)
            outcome = {
                "tool": name,
                "tool_call_id": call,
                "result": result,
                "withheld_result_keys": sorted(set(taken)),
                "absent": [a for a in absent if a.endswith("result")],
            }
        self._client.submit({**outcome, "span": self._where(span)}, timestamp=_when(span.end_time))

    def _inference(self, span: ReadableSpan, attributes: dict[str, Any]) -> None:
        wanted = ("gen_ai.system_instructions", "gen_ai.input.messages")
        messages, omitted = _parts(_value(attributes.get("gen_ai.input.messages")), "input_messages")
        instructions, dropped = _parts(_value(attributes.get("gen_ai.system_instructions")), "system_instructions")
        messages, withheld = scrub(messages, self._keys)
        self._client.submit(
            {
                "operation": attributes.get("gen_ai.operation.name"),
                "model": attributes.get("gen_ai.request.model"),
                "system_instructions": instructions,
                "input_messages": messages,
                "withheld_argument_keys": sorted(set(withheld)),
                "omitted_parts": omitted + dropped,
                "absent": [a for a in wanted if a not in attributes],
                "span": self._where(span),
            },
            timestamp=_when(span.start_time),
        )


def install(
    provider: TracerProvider,
    client: Tallwright,
    *,
    actor_authority: str | None = None,
    redact_keys: frozenset[str] = CREDENTIAL_KEYS,
) -> TallwrightSpanProcessor:
    """Add a :class:`TallwrightSpanProcessor` to ``provider``; the processor. Refuses a sampler that can drop.

    Only ``ALWAYS_ON`` is taken. The SDK's default, a parent-based sampler, follows an unsampled parent
    from another service and drops the span; a ratio sampler drops spans by design. A dropped span never
    reaches a processor, so it would be an action recorded nowhere, with nothing to show it is missing.
    """
    if provider.sampler is not ALWAYS_ON:
        raise SamplerDropsSpans(
            f"the provider samples with {provider.sampler.get_description()}, which can drop a span, and a dropped "
            "span is an action recorded nowhere. Build it with sampler=ALWAYS_ON and sample in your collector."
        )
    processor = TallwrightSpanProcessor(client, actor_authority=actor_authority, redact_keys=redact_keys)
    provider.add_span_processor(processor)
    return processor
