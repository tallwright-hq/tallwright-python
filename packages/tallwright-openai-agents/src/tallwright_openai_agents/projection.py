# SPDX-License-Identifier: Apache-2.0
"""What an OpenAI Agents SDK run's events become as content: the projection, and only that.

The one real decision an adapter makes (https://docs.tallwright.com/adapters, section 4). The functions
build plain JSON values and nothing else.

**Input items are an allowlist.** What the model is given arrives as Responses API input items. A
message, a function call and a function call's output are committed to; any other item, a ``reasoning``
item above all, or a type that does not exist yet, is replaced by a marker and named in
``omitted_input_items``: the unknown fails closed, and visibly. A function call's ``arguments`` arrive as
a JSON string; when they are a JSON object they are committed to as that object, so a credential key
inside them can be withheld like any other.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from tallwright_core.redact import CREDENTIAL_KEYS, scrub

#: The input items committed to. A message may come without a ``type``: an ``{"role", "content"}`` dict.
ITEM_TYPES = frozenset({"message", "function_call", "function_call_output"})

#: What stands where an item of another type was.
OMITTED = "[omitted: not a recorded input-item type]"


def _named(value: Any) -> str | None:
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else None


def _model(agent: Any) -> str | None:
    model = getattr(agent, "model", None)
    return model if isinstance(model, str) else _named(model) or (type(model).__name__ if model is not None else None)


def arguments_of(raw: Any, keys: frozenset[str] = CREDENTIAL_KEYS, *, path: str = "") -> tuple[Any, list[str]]:
    """A tool call's arguments: the JSON object they spell, with named credential keys withheld, or the text.

    A string that is not a JSON object is kept as it came: a key inside text is not a key.
    """
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return raw, []
        if not isinstance(parsed, (dict, list)):
            return raw, []
        raw = parsed
    return scrub(raw, keys, path=path)


def plain(value: Any) -> Any:
    """A result reduced to a JSON value: its own dump where it has one, its structure where it is one."""
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return plain(dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def project_item(item: Any, keys: frozenset[str] = CREDENTIAL_KEYS, *, path: str = "") -> tuple[Any, list[str], str | None]:
    """One input item, projected; the paths withheld; the type it was omitted as, if it was."""
    item = plain(item)
    if not isinstance(item, Mapping):
        return item, [], None
    kind = item.get("type", "message" if "role" in item else None)
    if kind not in ITEM_TYPES:
        return {"type": kind, "omitted": OMITTED}, [], str(kind)
    out = dict(item)
    if kind == "function_call" and "arguments" in out:
        out["arguments"], withheld = arguments_of(out["arguments"], keys, path=f"{path}.arguments")
        return out, withheld, None
    if kind == "message":
        out, withheld = scrub(out, keys, path=path)
        return out, withheld, None
    return out, [], None


def context_payload(
    agent: Any, system_prompt: str | None, input_items: Sequence[Any], keys: frozenset[str] = CREDENTIAL_KEYS
) -> dict[str, Any]:
    """What went to the model: the agent, its model, its instructions, the input items and the tools offered.

    ``withheld_argument_keys`` and ``omitted_input_items`` are present even when empty: "nothing was found"
    and "nothing was looked for" are opposite statements, and only these fields carry the difference.
    """
    projected = [project_item(item, keys, path=f"input[{i}]") for i, item in enumerate(input_items)]
    return {
        "agent": _named(agent),
        "model": _model(agent),
        "system_prompt": system_prompt,
        "input": [item for item, _, _ in projected],
        "tools": [_named(tool) for tool in getattr(agent, "tools", [])],
        "withheld_argument_keys": sorted({p for _, paths, _ in projected for p in paths}),
        "omitted_input_items": [f"input[{i}].{kind}" for i, (_, _, kind) in enumerate(projected) if kind],
    }


def action_payload(context: Any, agent: Any, tool: Any, keys: frozenset[str] = CREDENTIAL_KEYS) -> tuple[dict[str, Any], str]:
    """The call before it runs, with named credential arguments withheld; the tool's name, its kind of action."""
    name = getattr(context, "tool_name", None) or _named(tool) or type(tool).__name__
    args, withheld = arguments_of(getattr(context, "tool_arguments", None), keys)
    return (
        {
            "agent": _named(agent),
            "tool": name,
            "tool_call_id": getattr(context, "tool_call_id", None),
            "arguments": args,
            "withheld_argument_keys": sorted(set(withheld)),
        },
        name,
    )


def result_payload(context: Any, tool: Any, result: Any, keys: frozenset[str] = CREDENTIAL_KEYS) -> dict[str, Any]:
    """What the tool returned, as the agent received it, with named credential keys withheld.

    A tool that raised returns what the SDK made of the error for the model, and that is what is kept.
    """
    encoded, withheld = scrub(plain(result), keys)
    return {
        "tool": getattr(context, "tool_name", None) or _named(tool),
        "tool_call_id": getattr(context, "tool_call_id", None),
        "result": encoded,
        "withheld_result_keys": sorted(set(withheld)),
    }


def handoff_payload(from_agent: Any, to_agent: Any) -> dict[str, Any]:
    """A handoff: the agent that handed the conversation on, and the one that took it."""
    return {"from": _named(from_agent), "to": _named(to_agent)}
