# SPDX-License-Identifier: Apache-2.0
"""Named credential fields, replaced wherever an adapter finds them.

**Why this is here and not in one adapter.** A prompt in a request body is intended evidence and a
credential beside it is not: Anthropic's Messages API takes ``mcp_servers[].authorization_token``,
OpenAI's Responses API takes ``tools[].headers.Authorization``, an OAuth POST carries
``client_secret``. A tool that takes a credential as an ARGUMENT, which is most "call this API for
me" tools, is the same hole through a different door.

Two adapters refusing the same secret in two different implementations is two implementations that
will one day disagree about which one it is. Every adapter of every framework, whether it records
for Cloud Proof or for a self-hosted archive, takes this one. The adapter still decides WHERE to
look — a body, a tool's arguments — because only it knows its own shapes; what to replace, and what
to say about it, lives here.

**Why it matters when the content never leaves the machine.** Content an adapter commits to is
kept, and later disclosed to whoever checks the record. A credential inside it would be handed over
with it, and a commitment cannot be edited afterwards without breaking it.

**Why a denylist, when this codebase argues against them.** Headers and query keys take an allowlist
because the NAME survives it and costs nothing. A body and a tool call cannot: they ARE the
evidence, so an allowlist would leave the record saying nothing happened. The choice is incomplete
protection or a useless record, and what makes the first bearable is that the record names what was
withheld and under which path, so the list's effect is visible rather than assumed.
"""

from __future__ import annotations

from typing import Any

#: What replaces a value that must not be sealed. Visible on the face of the record: a reader must
#: never have to wonder whether a missing value was absent or removed.
REDACTED = "[redacted]"

#: Keys whose VALUES are a credential rather than evidence, matched on the WHOLE key and
#: case-insensitively, so ``max_tokens`` is untouched by ``token``.
#:
#: Incomplete by construction, like every denylist. An adapter passes its own set when an operator
#: names more.
CREDENTIAL_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "authorization_token",
        "client_secret",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)


#: Keys whose values are the MODEL'S OWN REASONING, matched the same way.
#:
#: Separate from :data:`CREDENTIAL_KEYS` because the reason is different and a reader of the
#: record should be able to tell the two apart by the path alone. A credential is withheld
#: because sealing it would put somebody's secret in a chain nobody can delete from. Reasoning
#: is withheld because this product says, on its front page, that it does not record it —
#: it is a flight recorder, not a mind reader, and a provider's chain-of-thought is neither
#: what the agent was told nor what it did.
#:
#: An adapter that sees a framework's messages projects each one onto an allowlist. An adapter
#: that sees transport bytes cannot project a body it did not design, so it does the same job
#: with the same tool the credentials use: named keys, replaced, with the path recorded.
#: Incomplete by construction, like every denylist, and visible in the record rather than
#: assumed.
#:
#: ``reasoning`` is in here knowing it is also an ordinary English word: a business API that
#: answers with a field of that name has it replaced. That is the trade, and it is made this
#: way round on purpose — over-redaction is visible on the face of the record and the
#: operator can narrow the set, while under-redaction puts a model's reasoning in an archive
#: that cannot be edited and contradicts the product's own claim. An operator who needs the
#: field passes their own set.
REASONING_KEYS = frozenset(
    {
        "reasoning",
        "reasoning_content",
        "reasoning_details",
        "redacted_thinking",
        "thinking",
    }
)


def scrub(value: Any, keys: frozenset[str], *, path: str = "") -> tuple[Any, list[str]]:
    """The value with every named key replaced, and the paths where they were.

    The PATH matters as much as the name: ``mcp_servers[0].authorization_token`` tells a reader
    which server was addressed with a credential, which is evidence, while the credential itself is
    not. Recording only "something was withheld" would be the same silence this refuses everywhere
    else.

    Returns the ORIGINAL object when nothing matched, so a caller can tell "nothing to do" from "a
    copy with something replaced" and leave untouched bytes untouched.
    """
    withheld: list[str] = []
    scrubbed = _walk(value, keys, path, withheld)
    return (value, withheld) if not withheld else (scrubbed, withheld)


def _walk(value: Any, keys: frozenset[str], path: str, withheld: list[str]) -> Any:
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, held in value.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).lower() in keys:
                out[key] = REDACTED
                withheld.append(here)
            else:
                out[key] = _walk(held, keys, here, withheld)
        return out
    if isinstance(value, list):
        return [_walk(item, keys, f"{path}[{i}]", withheld) for i, item in enumerate(value)]
    if isinstance(value, tuple):
        # A tuple is a sequence a caller can hand us as easily as a list — an SDK that returns
        # frozen structures, a hand-built payload, `dict(items)` gone the other way — and it used
        # to walk straight past this function with anything inside it intact. It comes back as a
        # LIST because that is what canonicalisation produces anyway: JSON has one sequence type,
        # so a tuple that survived to the seal would already have been serialised as an array.
        return [_walk(item, keys, f"{path}[{i}]", withheld) for i, item in enumerate(value)]
    return value
