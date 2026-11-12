# SPDX-License-Identifier: Apache-2.0
"""Content-addressing and self-describing multihash (SHA-256).

Zero external dependencies. SHA-256 is carried as a self-describing *multihash*
so a digest records *which* algorithm produced it — the algorithm-agility
property the seal spec needs for long-term verifiability. Only sha2-256 is supported in V1;
the structure leaves room for a future migration (e.g. to an SHA-3 / longer hash)
without breaking stored proofs.
"""

from __future__ import annotations

import hashlib
import hmac

# multicodec code for sha2-256 is 0x12; its digest length is 32 bytes (0x20).
SHA2_256_CODE = 0x12
SHA2_256_LENGTH = 32
# multibase prefix for base16, lower-case (RFC 4648). Keeps content addresses
# trivially inspectable and verifiable.
_MULTIBASE_BASE16_LOWER = "f"


def sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of ``data``."""
    return hashlib.sha256(data).digest()


def _uvarint_encode(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvarint cannot encode a negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _uvarint_decode(buf: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(buf):
            raise ValueError("truncated uvarint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("uvarint too long")


def multihash(data: bytes, *, algo: str = "sha2-256") -> bytes:
    """Return the self-describing multihash of ``data``.

    Layout: ``uvarint(code) || uvarint(length) || digest``.
    """
    if algo != "sha2-256":
        raise ValueError(f"unsupported hash algorithm: {algo!r}")
    digest = sha256(data)
    return _uvarint_encode(SHA2_256_CODE) + _uvarint_encode(len(digest)) + digest


def decode_multihash(mh: bytes) -> tuple[int, int, bytes]:
    """Return ``(code, length, digest)`` from a multihash, validating length."""
    code, pos = _uvarint_decode(mh, 0)
    length, pos = _uvarint_decode(mh, pos)
    digest = mh[pos:]
    if len(digest) != length:
        raise ValueError("multihash length does not match its declared length")
    return code, length, digest


def content_address(data: bytes) -> str:
    """Return a multibase (base16-lower) content address for ``data``.

    Used for ``payload_hash`` and for the record chain address. NOT for ``record_id``, which the
    recorder mints as a UUID4 and the reference pipeline sets to a human label.
    """
    return _MULTIBASE_BASE16_LOWER + multihash(data).hex()


def address_from_digest(digest: bytes) -> str:
    """The same content address as :func:`content_address`, from a digest already computed.

    For data that arrives in pieces and must not be held whole. A streamed response body is the
    case this exists for: the transport adapter folds each chunk into a ``hashlib`` object and keeps
    only the prefix it is allowed to seal, so a multi-gigabyte download costs the recorder a
    constant amount of memory instead of twice the body.

    The knowledge of what an address LOOKS like stays in this module, which is the point. A caller
    assembling the multibase prefix and the multicodec header itself would be a second place that
    knows the format, and a second place is a place that one day answers differently.
    """
    if len(digest) != SHA2_256_LENGTH:
        raise ValueError(
            f"expected a {SHA2_256_LENGTH}-byte sha2-256 digest, got {len(digest)} bytes"
        )
    header = _uvarint_encode(SHA2_256_CODE) + _uvarint_encode(SHA2_256_LENGTH)
    return _MULTIBASE_BASE16_LOWER + (header + digest).hex()


#: How long a per-record salt is, everywhere, without exception.
#:
#: It is not a tuning knob. ``SHA-256(salt ‖ plaintext)`` commits to the CONCATENATION and not to
#: the SPLIT, so if the length were free, every ``k`` would give a second valid reading:
#: ``(salt ‖ plaintext[:k], plaintext[k:])`` opens the very same address. An operator could then
#: disclose a TRUNCATED payload — pushing the amount, the account, the instruction into what they
#: call the salt — and a court's own verifier would confirm it opens. Because RFC 8785 sorts the
#: keys, the choppable prefix is deterministic and starts with the fields most worth withholding.
#:
#: A fixed length removes the second reading: there is exactly one way to cut 32 bytes off the front.
#: Found 2026-08-25 by adversarial review, demonstrated against a real record before it was fixed.
SALT_LEN = 32


class MalformedSalt(ValueError):
    """A salt that is not exactly :data:`SALT_LEN` bytes. Not a mismatch — an unreadable disclosure.

    Kept distinct because the two say completely different things to a court. "This disclosure does
    not open the address" accuses the operator of giving a false account of their own record. "This
    file is not in the format" says nothing about the record at all, and rendering the second as the
    first is exactly the kind of overstatement this codebase refuses everywhere else.
    """


def opens_address(address: str, salt: bytes, plaintext: bytes) -> bool:
    """Does this salt and this plaintext produce that committed address?

    The whole check a court performs when the archive holds no content — the operator discloses the
    two inputs, anyone recomputes, and no state belonging to the recorder is involved at any point.
    That is why it keeps working after the recorder is gone, and why it lives in the spine
    rather than in the service.

    The salt is why an address is not a search key. Without it, a short payload ("Termin abgesagt")
    could be recovered from its hash by trying candidates; with it, the operator holds the one thing
    that opens the commitment. Lose the salt and the record can never be opened again — the chain
    still proves it existed unaltered at that position, and nothing proves what it said.

    Raises :class:`MalformedSalt` if the salt is not exactly :data:`SALT_LEN` bytes. That check is
    what makes the split unique and therefore what makes this a commitment to the PAIR rather than
    to their concatenation — see the note on :data:`SALT_LEN`.
    """
    if len(salt) != SALT_LEN:
        raise MalformedSalt(
            f"a salt is exactly {SALT_LEN} bytes; this one is {len(salt)}. Without a fixed length "
            "the same address opens under many different splits, so a truncated payload would "
            "verify as the whole one."
        )
    return content_address(salt + plaintext) == address


def is_content_address(value: str) -> bool:
    """Is this string an address this module could have produced?

    Three places asked `value.startswith("f")` instead, so `'f'` was a well-formed
    address, and so were `'frei'`, `'f' + 'z' * 68`, a truncated digest and an
    upper-case one. An archive reporting OK over a record whose payload_hash commits
    to nothing leaves a court with nothing to recompute against, which is the whole of
    the disclosure story when the archive holds no content.

    It lives here for the reason `address_from_digest` gives: a second place that knows
    the format is a place that one day answers differently. Deliberately NOT a validator
    on `Record.payload_hash` — the spine and verifier suites build link-only records with
    stub hashes, and a schema validator would turn an existing bad log into a parse
    failure instead of a named finding.
    """
    if not value.startswith(_MULTIBASE_BASE16_LOWER):
        return False
    body = value[1:]
    # Upper-case hex is a DIFFERENT multibase ('F'), so a body that is not its own
    # lower-case did not come from here even when it decodes.
    if len(body) % 2 or body != body.lower():
        return False
    try:
        code, length, digest = decode_multihash(bytes.fromhex(body))
    except ValueError:
        return False
    return code == SHA2_256_CODE and length == SHA2_256_LENGTH and len(digest) == SHA2_256_LENGTH


def decode_content_address(addr: str) -> bytes:
    """Inverse of :func:`content_address`; returns the raw multihash bytes."""
    if not addr or addr[0] != _MULTIBASE_BASE16_LOWER:
        raise ValueError("unsupported multibase prefix (expected base16 'f')")
    return bytes.fromhex(addr[1:])


def verify(data: bytes, mh: bytes) -> bool:
    """Return True iff ``mh`` is the multihash of ``data`` (constant-time)."""
    try:
        expected = multihash(data, algo="sha2-256")
    except ValueError:
        # FAIL CLOSED. Unreachable while sha2-256 is the only algorithm, but this module
        # documents an algorithm migration as the point of the multihash envelope, and the
        # migration is exactly when this branch starts to matter. `return True` here would
        # make verify() answer True for ANY mh; the mutation lane found nothing pinning the
        # direction, and `# pragma: no cover` meant coverage never would.
        return False
    return hmac.compare_digest(expected, mh)
