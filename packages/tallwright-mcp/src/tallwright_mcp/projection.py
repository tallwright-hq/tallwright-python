# SPDX-License-Identifier: Apache-2.0
"""What an MCP tool call becomes as content: the call, its outcome, and the keys withheld from both.

The one real decision an adapter makes (https://docs.tallwright.com/adapters, section 4). The functions
build plain JSON values and nothing else, so a Cloud Proof session and a self-hosted one commit to the
same projection of the same call. None of them imports the MCP SDK: a result is reduced by its own dump,
whatever type this SDK version wraps it in.
"""

from __future__ import annotations

from typing import Any

from tallwright_core.redact import CREDENTIAL_KEYS, scrub


def action_type(name: str) -> str:
    """The kind of action a call to tool ``name`` is: ``mcp:<name>``."""
    return f"mcp:{name}"


def arguments(name: str, server: str, args: dict[str, Any] | None, keys: frozenset[str] = CREDENTIAL_KEYS) -> dict[str, Any]:
    """The call, with named credential arguments replaced and the paths where they were.

    ``withheld_argument_keys`` is present even when empty, so a reader can tell "nothing was found" from
    "nothing was looked for".
    """
    cleaned, withheld = scrub(args, keys)
    return {"server": server, "tool": name, "arguments": cleaned, "withheld_argument_keys": sorted(set(withheld))}


def outcome(name: str, server: str, result: Any, keys: frozenset[str] = CREDENTIAL_KEYS) -> dict[str, Any]:
    """What the tool answered, with named credential values replaced and their paths kept.

    "Issue me an access token" is an ordinary tool call, and its answer is as much a secret as an argument
    is. ``withheld_result_keys`` is present even when empty, for the reason :func:`arguments` gives.
    """
    cleaned, withheld = scrub(plain(result), keys)
    return {"server": server, "tool": name, "result": cleaned, "withheld_result_keys": sorted(set(withheld)), "ok": True}


def failure(name: str, server: str, error: str) -> dict[str, Any]:
    """The outcome when the call RAISED: the exception's type only, never its message."""
    return {"server": server, "tool": name, "error": error, "ok": False}


def plain(value: Any) -> Any:
    """An SDK object reduced to a JSON value, without importing the SDK.

    A fair attempt that keeps the STRUCTURE where there is one: ``str()`` over a result object would record
    the repr of a wrapper instead of what came back.
    """
    for attr in ("model_dump", "dict"):
        dump = getattr(value, attr, None)
        if callable(dump):
            return dump()
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    return str(value)
