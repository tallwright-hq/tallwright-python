# SPDX-License-Identifier: Apache-2.0
"""The commitment: the content stays on this machine, and only its salted address travels.

``payload_hash`` is the address of ``salt ‖ content``, exactly as the exhibit format specifies it
(https://docs.tallwright.com/exhibits, §1 and §6) and as ``tallwright_core.hashing`` computes it. The salt is 32
random bytes from the operating system, drawn per record. The pair is the disclosure a court opens
the address with, in the two keys the public verifier reads, and it is written to the caller's
evidence directory and nowhere else.

**Why a salt at all.** An unsalted address of a short content is a search key: anybody holding the
exhibit confirms a guess by hashing it. With the salt, the holder of the pair is the only party who
can say what an address stands for, and the door that recorded it is not one of them.

**Why nothing here raises about the content.** An error message is the one thing an integrator pastes
into a ticket, and an error tracker records the local variables of every frame an exception passes
through. So content that has no one byte form is not raised about here, in a frame that holds it: it
is RETURNED as a :class:`Refusal`, which names the type and never the value, and the caller raises it
after it has let go of the content. The encoder's own exception, whose ``object`` is the whole text, is
caught and dropped where it happens, so it is nobody's ``__context__`` either.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from typing import Any

from tallwright_core.canonical import CanonicalizationError, canonicalize
from tallwright_core.hashing import SALT_LEN, content_address

#: What ``capture`` takes, and the one byte form each has. ``str`` is UTF-8, and a JSON object or
#: array is its RFC 8785 canonical form, the project's one canonicalisation, so the same object
#: commits to the same bytes whoever builds it.
Content = bytes | bytearray | memoryview | str | dict[str, Any] | list[Any]


@dataclass(frozen=True)
class Refusal:
    """Why some content has no one byte form: its kind and a sentence, never the content."""

    kind: type[Exception]
    why: str

    def error(self) -> Exception:
        return self.kind(f"{self.why}. Nothing was written or sent")


def byte_form(content: object) -> bytes | Refusal:
    """The exact bytes that are committed to, or a :class:`Refusal`. Never raises."""
    if isinstance(content, (bytes, bytearray, memoryview)):
        return bytes(content)
    if isinstance(content, str):
        try:
            return content.encode("utf-8")
        except UnicodeEncodeError:
            return Refusal(ValueError, "this text is not valid Unicode (it holds a lone surrogate), so it has "
                                       "no UTF-8 form to commit to")
    if isinstance(content, (dict, list)):
        try:
            return canonicalize(content)
        except CanonicalizationError:
            return Refusal(
                ValueError,
                "this JSON value has no RFC 8785 form (a key that is not text, a number outside what JSON "
                "carries exactly, or a value that is not JSON), so it has no one byte form to commit to",
            )
    return Refusal(
        TypeError,
        f"content is bytes, text, or a JSON object or array, not {type(content).__name__}: anything else "
        "has more than one byte form, and a commitment is to exactly one",
    )


def b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


@dataclass(frozen=True)
class Commitment:
    """The content's bytes and the salt they are committed under. Neither is in a repr."""

    plaintext: bytes = field(repr=False)
    salt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.salt) != SALT_LEN:
            raise ValueError(
                f"a salt is exactly {SALT_LEN} bytes; this one is {len(self.salt)}. A free length "
                "would let the same address open under a shorter content"
            )

    @classmethod
    def of(cls, content: object) -> Commitment | Refusal:
        """A fresh commitment, the content's byte form under a new salt, or why there is none."""
        data = byte_form(content)
        if isinstance(data, Refusal):
            return data
        return cls(data, secrets.token_bytes(SALT_LEN))

    @property
    def payload_hash(self) -> str:
        """The address the door is sent, and the only thing about the content that leaves."""
        return content_address(self.salt + self.plaintext)

    def disclosure(self) -> dict[str, str]:
        """The pair, as the public verifier's ``--disclosure`` reads it (spec §6)."""
        return {"salt": b64(self.salt), "payload_b64": b64(self.plaintext)}

    def __repr__(self) -> str:
        return f"Commitment(payload_hash={self.payload_hash!r})"
