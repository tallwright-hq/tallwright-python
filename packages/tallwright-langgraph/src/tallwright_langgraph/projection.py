# SPDX-License-Identifier: Apache-2.0
"""What a LangChain/LangGraph v1 agent's events become as content: the projection, and only that.

This is the one real decision an adapter makes (https://docs.tallwright.com/adapters, section 4):
which fields of what the framework hands it are committed to, and which are left out. Everything
after that, the commitment, the salt, the evidence and the sending, belongs to the recorder the
middleware hands the content to. The functions here build plain JSON values and nothing else, so the
Cloud Proof middleware and a self-hosted one commit to the same projection of the same event.

**Two contracts, two functions.** A framework MESSAGE is an object whose schema this module names,
and from which a provider's reasoning must be excluded; a tool RESULT is arbitrary business data,
and is kept whole. One shared "dump, then subtract" helper for both applied every rule written for
messages, by key name and at every depth, to data whose shape nobody here can know: it deleted
evidence, and two different approvals encoded to the same value. So the message is an ALLOWLIST
projection, closed against any field a provider adds later, and the result encoder filters nothing
but the named credential keys every adapter withholds (``tallwright_core.redact``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from langchain.agents.middleware import ModelRequest, ToolCallRequest
from langchain_core.messages import BaseMessage
from tallwright_core.redact import CREDENTIAL_KEYS, scrub

#: The fields of a message that are committed to. Anything else (``additional_kwargs``,
#: ``response_metadata``, ``usage_metadata`` and whatever a provider adds tomorrow) is absent by
#: construction, and named in ``omitted_message_fields``.
MESSAGE_FIELDS = (
    "type",
    "id",
    "name",
    "content",
    "tool_calls",
    "invalid_tool_calls",
    "tool_call_id",
    "status",
    "artifact",
)

#: The content blocks that are committed to. Anything else, a provider's thinking block or a block
#: type that does not exist yet, is replaced by a marker: the unknown fails closed, and visibly.
CONTENT_BLOCK_TYPES = frozenset(
    {
        "text",
        "tool_use",
        "tool_result",
        "image",
        "document",
        "server_tool_use",
        "web_search_tool_result",
        "citation",
    }
)

#: What stands where a block of another type was.
OMITTED = "[omitted: not a recorded content-block type]"


def model_id(model: Any) -> str:
    """The model's name, from a string or the attribute a chat model keeps it in."""
    if isinstance(model, str):
        return model
    for attr in ("model", "model_name"):
        value = getattr(model, attr, None)
        if isinstance(value, str):
            return value
    return type(model).__name__


def project_block(block: Any, keys: frozenset[str] = CREDENTIAL_KEYS, *, path: str = "") -> tuple[Any, list[str]]:
    """One content block, with named credential values replaced wherever they sit.

    A ``tool_use`` block carries the same arguments the tool call does, so withholding a credential
    from the action alone would leave it in the context by a second door. Returns what it took as well
    as what is left: a redaction nobody can see cannot be told from a block that never carried one.
    """
    if isinstance(block, Mapping):
        kind = block.get("type")
        if kind not in CONTENT_BLOCK_TYPES:
            return {"type": kind, "omitted": OMITTED}, []
        # With the path: `token` alone does not tell a reader which of five blocks was cut.
        return scrub(dict(block), keys, path=path)
    return block, []


def names_dropped(full: Mapping[str, Any]) -> list[str]:
    """The NAMES the allowlist dropped from a message, never their values.

    The complement of the allowlist, so it deletes nothing and names a carrier a provider invents
    tomorrow. Without it, a message carrying a provider's reasoning under ``additional_kwargs`` or
    ``response_metadata`` projected to the same bytes as one carrying none: the omission was not only
    unmarked, it was undetectable. One level deep, because those carriers sit under a container whose
    name alone says nothing; empty values are skipped, so it reports what was dropped.
    """
    names: list[str] = []
    for key in sorted(set(full) - set(MESSAGE_FIELDS)):
        value = full[key]
        if value is None or value is False or value == {} or value == [] or value == "":
            continue
        if isinstance(value, Mapping):
            names += [f"{key}.{inner}" for inner in sorted(value)]
        else:
            names.append(key)
    return names


def project_message(message: Any, keys: frozenset[str] = CREDENTIAL_KEYS) -> tuple[Any, list[str], list[str]]:
    """A framework message, projected onto the fields named above; the paths withheld; the names dropped.

    ``tool_calls`` and ``invalid_tool_calls`` are named fields, and they carry the arguments a tool was
    called with, for most "call this API for me" tools somebody else's credential. So the same keys are
    replaced here as in the action: the arguments appear twice, and withholding one of them is not
    withholding.
    """
    dump = getattr(message, "model_dump", None)
    if not callable(dump):
        return str(message), [], []
    full = dump(mode="json")
    out = {k: full[k] for k in MESSAGE_FIELDS if k in full}
    omitted = names_dropped(full)
    withheld: list[str] = []
    content = out.get("content")
    if isinstance(content, list):
        projected = [project_block(b, keys, path=f"content[{i}]") for i, b in enumerate(content)]
        out["content"] = [b for b, _ in projected]
        withheld += [p for _, paths in projected for p in paths]
    for field in ("tool_calls", "invalid_tool_calls"):
        if field in out:
            out[field], taken = scrub(out[field], keys)
            withheld += taken
    return out, withheld, omitted


def encode_result(value: Any, keys: frozenset[str] = CREDENTIAL_KEYS, *, path: str = "") -> tuple[Any, list[str]]:
    """A tool RESULT as a JSON value, kept whole but for the named credential keys; the paths withheld.

    A result's ``signature``, ``reasoning`` or ``thought`` are evidence, and stay. The one special case
    is a framework message a tool returned, which is projected like any other message.
    """
    if isinstance(value, BaseMessage):
        projected, withheld, _omitted = project_message(value, keys)
        return projected, withheld
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        taken: list[str] = []
        for k, v in value.items():
            here = f"{path}.{k}" if path else str(k)
            out[k], paths = encode_result(v, keys, path=here)
            taken += paths
        return out, taken
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value, []
    if isinstance(value, (list, tuple)):
        items = [encode_result(v, keys, path=f"{path}[{i}]") for i, v in enumerate(value)]
        return [v for v, _ in items], [p for _, paths in items for p in paths]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return encode_result(dump(mode="json"), keys, path=path)
    return str(value), []


def dump_messages(messages: Sequence[Any], keys: frozenset[str]) -> tuple[list[Any], list[str], list[str]]:
    """Every message projected; every path withheld; every name dropped, under ``messages[i]``."""
    projected = [project_message(m, keys) for m in messages]
    return (
        [m for m, _, _ in projected],
        [p for _, paths, _ in projected for p in paths],
        [f"messages[{i}].{name}" for i, (_, _, names) in enumerate(projected) for name in names],
    )


def dump_tools(tools: Sequence[Any]) -> list[Any]:
    """The tools the model was offered: name and description, or the mapping it was given as."""
    out: list[Any] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if name is not None:
            out.append({"name": name, "description": getattr(tool, "description", "")})
        elif isinstance(tool, Mapping):
            out.append(dict(tool))
        else:
            out.append(str(tool))
    return out


def model_payload(request: ModelRequest, keys: frozenset[str] = CREDENTIAL_KEYS) -> dict[str, Any]:
    """What went to the model, and which named credentials were taken out of it.

    ``withheld_argument_keys`` and ``omitted_message_fields`` are present even when empty: "nothing was
    found to withhold" and "nothing was looked for" are opposite statements about whether a credential
    or a provider's reasoning could be sitting in this prompt, and only these fields carry the
    difference.
    """
    system, taken, dropped = (
        project_message(request.system_message, keys) if request.system_message is not None else (None, [], [])
    )
    messages, more, also = dump_messages(request.messages, keys)
    return {
        "model": model_id(request.model),
        "system_message": system,
        "messages": messages,
        "tools": dump_tools(request.tools),
        "withheld_argument_keys": sorted(set(taken + more)),
        "omitted_message_fields": sorted(set([f"system_message.{n}" for n in dropped] + also)),
    }


def action_payload(request: ToolCallRequest, keys: frozenset[str] = CREDENTIAL_KEYS) -> tuple[dict[str, Any], str]:
    """The call, with named credential arguments replaced and the paths where they were; the tool's name."""
    call = request.tool_call
    name = getattr(request.tool, "name", None) or call.get("name")
    args, withheld = scrub(call.get("args"), keys)
    return (
        {
            "tool": name,
            "args": args,
            "tool_call_id": call.get("id"),
            "withheld_argument_keys": sorted(set(withheld)),
        },
        str(name),
    )


def result_payload(request: ToolCallRequest, result: Any, keys: frozenset[str] = CREDENTIAL_KEYS) -> dict[str, Any]:
    """The tool's outcome, kept whole, and the paths the credential keys took out of it.

    ``withheld_result_keys`` is present even when empty. A business field whose NAME collides with a
    credential key is replaced, and silently that would read as the tool's own answer.
    """
    encoded, withheld = encode_result(result, keys)
    return {
        "tool_call_id": request.tool_call.get("id"),
        "result": encoded,
        "withheld_result_keys": sorted(set(withheld)),
    }


def error_payload(request: ToolCallRequest, error: str) -> dict[str, Any]:
    """The outcome when the tool RAISED: the exception's type only, never its message.

    A message can carry provider or third-party detail nothing here has projected; the fact the record
    needs is that the action did not complete normally.
    """
    return {"tool_call_id": request.tool_call.get("id"), "error": error}
