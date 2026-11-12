# SPDX-License-Identifier: Apache-2.0
"""Hardened RFC 8785 (JCS) canonicalization.

Wraps ``rfc8785.dumps`` with fail-closed guards so a hostile or malformed input becomes
a *typed, catchable* error instead of a crash, a silent drop, or non-deterministic bytes:

  - **non-finite floats** (NaN / +-Infinity) are rejected — RFC 8785 has no representation
    for them, and letting one through would make a hash irreproducible;
  - **nesting depth is bounded** (``MAX_CANONICAL_DEPTH``) so a deeply-nested structure
    cannot exhaust the interpreter stack (a cheap capture-path DoS);
  - **total work is bounded** (``MAX_CANONICAL_NODES``) so a shallow but shared-reference
    DAG cannot expand to exponentially many nodes and hang the serializer;
  - any residual library-level failure (unserializable type, non-string key, recursion)
    is re-raised as :class:`CanonicalizationError`.

For every input **within the depth / total-work bounds**, the output is byte-for-byte
identical to a raw ``rfc8785.dumps`` call — so record hashes are unchanged. Inputs that
exceed those bounds (or that ``rfc8785`` itself rejects) raise a TYPED error rather than hanging or
silently producing a non-reproducible value. What the capture layer then does depends on its mode:
under the SHIPPED DEFAULT (``fail_closed=False``) the error is counted and sealed as an auditable
rupture marker, and the agent keeps serving; with ``fail_closed=True`` it propagates and NOTHING is
sealed — no gap record, no rupture marker, and no unrecorded action either.
The bounds are set far above any real record or tool payload, so this only ever trips a
pathological/hostile input.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import rfc8785

# JSON nesting deeper than this is rejected before serialization. Real records and tool
# payloads are shallow; this only trips a pathological/hostile input.
MAX_CANONICAL_DEPTH = 64
# Upper bound on the total number of values visited during the guard walk. Bounds total
# work so a shared-reference DAG (shallow but exponentially wide when traversed as a tree)
# is rejected quickly instead of hanging. JSON from ``model_dump`` is a tree (node count ~=
# payload size), so this only rejects a genuinely enormous or hostile-DAG payload — which
# then becomes an auditable gap, never an unbounded hang.
MAX_CANONICAL_NODES = 1_000_000


class CanonicalizationError(ValueError):
    """An input cannot be deterministically canonicalized under RFC 8785 (JCS)."""


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 (JCS) canonical bytes of ``obj``, or raise CanonicalizationError.

    Guards run *before* serialization so depth/finiteness/total-work violations are reported
    without ever entering the C serializer with a hostile input. For any already-canonicalizable
    input the output is byte-identical to a raw ``rfc8785.dumps`` call.
    """
    remaining = MAX_CANONICAL_NODES

    def guard(node: Any, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise CanonicalizationError(f"input exceeds MAX_CANONICAL_NODES={MAX_CANONICAL_NODES}")
        if depth > MAX_CANONICAL_DEPTH:
            raise CanonicalizationError(f"nesting exceeds MAX_CANONICAL_DEPTH={MAX_CANONICAL_DEPTH}")
        if isinstance(node, bool):
            return  # bool before int/float; nothing to recurse into
        if isinstance(node, float):
            if not math.isfinite(node):
                raise CanonicalizationError(f"non-finite float {node!r} has no RFC 8785 representation")
            return
        if isinstance(node, Mapping):
            for value in node.values():
                guard(value, depth + 1)
            return
        if isinstance(node, (str, bytes)):
            return  # sized but not a container to descend
        if isinstance(node, Sequence):
            for item in node:
                guard(item, depth + 1)

    guard(obj, 0)
    try:
        return rfc8785.dumps(obj)
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        # rfc8785's own IntegerDomainError / etc. subclass ValueError; normalize them all
        # (and any residual serializer failure) to one typed, catchable error.
        raise CanonicalizationError(str(exc)) from exc
