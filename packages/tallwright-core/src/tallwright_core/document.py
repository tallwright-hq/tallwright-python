# SPDX-License-Identifier: Apache-2.0
"""Reading a document whose meaning does not depend on who reads it.

JSON permits an object to carry the same key twice, and every parser resolves that its own way:
``json.loads`` keeps the LAST, a person reading the file sees the FIRST, and another tool may see
either. A file with two readings is not a document — and an exhibit is a document before it is
anything else.

What that buys a producer, measured against this project's own golden vector before this module
existed: insert ``"action_type":"password_reset",`` in front of the real ``"action_type":"wire_transfer"``
and the parsed object is unchanged, so the canonicalization is unchanged, so **every signature still
verifies**. The court-facing tool prints its PASS lines for a file that reads as a different action
than the one it authenticates. No key is forged; the ambiguity is in the format.

So it is refused, at the door, wherever this project reads a document it will act on.

**Nor is a document read past a depth nobody writes.** ``json.loads`` recurses once per level of
nesting, and two hundred thousand ``[`` made it raise RecursionError — which is not a ValueError, so it
passed every reader's "unreadable" branch: the verifier printed a traceback and exited 1, the code for
evidence that was tampered with, and the same program in a browser lost its WebAssembly worker, whose
stack runs out before Python's recursion check does. The depth is therefore counted BEFORE anything
recurses, and a document past :data:`MAX_DOCUMENT_DEPTH` is refused as the ValueError it always should
have been.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .canonical import MAX_CANONICAL_DEPTH

__all__ = ["AmbiguousDocument", "DocumentTooDeep", "MAX_DOCUMENT_DEPTH", "load_document"]

#: The deepest a document read here may nest, its own outermost object or array counting as one. An
#: exhibit nests 6 levels, a policy 4 and a disclosure 1; the deepest object this project canonicalises
#: nests MAX_CANONICAL_DEPTH + 1, and this leaves room for it inside an envelope as deep again. CPython
#: 3.12 raises RecursionError near 3,000 levels and a browser's WebAssembly stack gives out sooner, so
#: the bound sits far below both, and far above anything real.
MAX_DOCUMENT_DEPTH = 2 * MAX_CANONICAL_DEPTH

#: One JSON string — closed, or running to the end of a text that never closes it — or one bracket. The
#: possessive quantifiers consume a string's run once and never give it back, so no input makes the scan
#: restart inside a string it has passed: the scan is linear in the text.
_TOKENS = re.compile(r'"(?:[^"\\]++|\\.)*+(?:"|\\?\Z)|[\[\]{}]', re.DOTALL)


class AmbiguousDocument(ValueError):
    """A document that reads one way to one parser and another way to the next."""


class DocumentTooDeep(ValueError):
    """A document nested deeper than anything this project writes, refused before it is parsed."""


def _no_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise AmbiguousDocument(
                f"the key {key!r} appears twice in one object. A reader of this file and a parser "
                f"of it would not agree on what it says, so it is not read here."
            )
        seen[key] = value
    return seen


def _deeper_than(text: str, bound: int) -> bool:
    """Whether any point of ``text`` lies inside more than ``bound`` objects and arrays.

    Brackets inside strings are not nesting, and an escaped quote does not end a string. Malformed text
    is not this function's to judge: it counts what it finds, and the parser refuses the rest.
    """
    if text.count("[") + text.count("{") <= bound:
        return False  # a text cannot nest deeper than it has openings; nearly every document stops here
    depth = 0
    for token in _TOKENS.finditer(text):
        first = text[token.start()]
        if first in "[{":
            depth += 1
            if depth > bound:
                return True
        elif first in "]}":
            depth -= 1
    return False


def load_document(text: str | bytes) -> Any:
    """``json.loads``, refusing any object that carries a key twice and any document nested deeper than
    :data:`MAX_DOCUMENT_DEPTH`.

    Raises :class:`AmbiguousDocument` for a repeated key, :class:`DocumentTooDeep` for the nesting, and
    ``json.JSONDecodeError`` — a ``ValueError`` like both — for anything else malformed, so a caller that
    already handles unreadable input keeps handling it. Bytes are decoded the way ``json.loads`` decodes
    them.
    """
    source = text.decode(json.detect_encoding(text), "surrogatepass") if isinstance(text, bytes) else text
    if _deeper_than(source, MAX_DOCUMENT_DEPTH):
        raise DocumentTooDeep(
            f"it is nested deeper than {MAX_DOCUMENT_DEPTH} levels. Nothing this project writes comes "
            f"near that, and a parser following it would run out of stack before it ran out of "
            f"document, so it is not read here."
        )
    return json.loads(source, object_pairs_hook=_no_repeats)
