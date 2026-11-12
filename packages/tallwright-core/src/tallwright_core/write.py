# SPDX-License-Identifier: Apache-2.0
"""Replacing a document's contents in one step, or not at all.

The mirror of :mod:`tallwright_core.document`: that one refuses to READ a file that says two
things, this one refuses to LEAVE a file that is half of one.

``Path.write_text`` opens with ``"w"``: it truncates first and writes second. A crash or a full
disk between those leaves a file that is neither the old contents nor the new " and the files this
matters for are the ones that hold everything. `fleet.json` carries every tenant an operator has,
every API-key hash and the witness identity they all anchor to; the operator config carries the
checkpoint key's public half and the origin. Losing one of those to a torn write costs a customer
list, not a cache.

**This does not claim durability.** Without an ``fsync`` a crash can lose the write entirely. What
it cannot do any more is lose it halfway, and a lost write leaves the OLD file " which is a thing
somebody can still read " where a torn one leaves nothing.

The scratch lives in the SAME directory, because ``os.replace`` is only atomic within one
filesystem. Where the target directory is sealed append-only, the scratch has to live outside it
instead and the rename goes in " that case is not this one and
``Archive._stage_anchor_file`` handles it separately.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["write_document"]


def write_document(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` so a reader sees either the old contents or all of the new."""
    scratch = path.with_name(f".{path.name}.part")
    scratch.write_text(text, encoding="utf-8")
    os.replace(scratch, path)
