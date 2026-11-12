# SPDX-License-Identifier: Apache-2.0
"""The exhibit of one record: handed over once by its link, checked against what was sent, filed beside it.

An exhibit leaves by a one-time link: the backoffice
asks the fleet for one, and the fleet's exhibit door answers ``GET …/v1/exhibits/<token>`` with a zip of
three files, once, within fifteen minutes, to whoever holds the link. On the hosted fleet the link names
the book beneath the host (``https://exhibits.example/<book>/v1/exhibits/<token>``), and the host strips
it on the way in. This module reads such a zip and says which record it is of, field by field. Verifying
the exhibit is not this package's job: that is the public verifier's, run by whoever wants to check,
with the disclosure this package wrote.

**What the door's answers mean.** 409: the door could not build the exhibit now and says why — most
often that no witness has covered the record yet, but also a record it does not hold or an archive that
does not answer for itself — and the link was NOT used, so it opens again until it expires. 410: the
link was used once, by somebody. 404: not a link the door can open, expired or never valid. An answer
that broke off may have spent the link: the door marks it used as it hands the exhibit over.

**A link is a credential.** Whoever holds it takes the exhibit, so no message here repeats it. Keep it
out of logs and traces too: a request instrumented by a tracing library records its address.

**Or an environment's export key takes it, with no link and no click.** The same door
answers ``GET …/v1/records/<record id, base64url>/exhibit`` with the same zip for that environment's
export key, a second credential that reads and records nothing. 401: no such key — never issued,
replaced or withdrawn. 404: this environment holds no such record. 409: not witnessed yet. Nothing is
spent by asking, so any of them may simply be asked again once its reason has gone.
"""

from __future__ import annotations

import base64
import http.client
import io
import re
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any

from tallwright_core.document import load_document
from tallwright_core.hashing import is_content_address
from tallwright_core.schema import Record

from . import transport
from .errors import ExhibitError, ExhibitNotReady, ExportKeyRefused, LinkSpent

#: The files an exhibit is, as the fleet's export writes them.
FILES = ("evidence.json", "our-claims.json", "policy.json")
PREFIX = "/v1/exhibits/"
#: An exhibit is a few kilobytes whatever the size of the log; this is far above any.
MAX_EXHIBIT = 16 << 20
#: One folder, the door's own name for it, and the three files in it: nothing that could land elsewhere.
_ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}/(?:evidence|our-claims|policy)\.json")


def checked_link(link: str) -> str:
    """An exhibit link: https (or loopback), its path ending in the door's path and one token."""
    parts = transport.checked_address(link, "an exhibit link")
    before, found, token = parts.path.rpartition(PREFIX)
    if not found or not token or "/" in token or (before and not before.startswith("/")):
        raise ValueError(
            f"this is not an exhibit link: its path does not end in {PREFIX}<token> (the link itself is "
            "not repeated here, because whoever holds it can take the exhibit)"
        )
    return link


def fetch(link: str, timeout: float) -> bytes:
    """The zip a link hands over, or the door's refusal as the error it is. The link is not retried:
    a second request for a link that was handed over is a request for a spent one."""
    try:
        status, body = transport.fetch(checked_link(link), timeout, MAX_EXHIBIT)
    except (OSError, http.client.HTTPException) as failed:
        status, body, broke = 0, b"", f"{type(failed).__name__}: {getattr(failed, 'reason', failed)}"
    else:
        broke = ""
    if broke:
        raise ExhibitError(
            f"the exhibit link could not be opened ({broke}). If the door had begun to hand the exhibit "
            "over, the link is spent; if it answers 410 next, ask the backoffice for a new one"
        )
    if status != 200:
        kind = ExhibitNotReady if status == 409 else LinkSpent if status == 410 else ExhibitError
        raise kind(f"the exhibit door answered {status}: {transport.said_in(body)}", status=status)
    if len(body) > MAX_EXHIBIT:
        raise ExhibitError(f"the answer is larger than {MAX_EXHIBIT} bytes, which no exhibit is", status=status)
    return body


#: Where an export key takes an exhibit: ``<exhibit address>`` + RECORDS + <record id, base64url> + EXHIBIT.
RECORDS = "/v1/records/"
EXHIBIT = "/exhibit"


def export_url(url: str, record_id: str) -> str:
    """The address an export key asks for one record's exhibit at, beneath the environment's exhibit address."""
    transport.checked_address(url, "the exhibit door")
    encoded = base64.urlsafe_b64encode(record_id.encode("utf-8")).rstrip(b"=").decode("ascii")
    return url.rstrip("/") + RECORDS + encoded + EXHIBIT


def take(url: str, key: transport.Key, record_id: str, timeout: float) -> bytes:
    """The zip the exhibit door hands this environment's export key for one record, or its refusal.

    Asked once and never retried here: nothing is spent by asking, so a caller who sees why can ask
    again, and a loop of ours would hide the sentence that says why.
    """
    try:
        status, body = transport.fetch(export_url(url, record_id), timeout, MAX_EXHIBIT, key)
    except (OSError, http.client.HTTPException) as failed:
        status, body, broke = 0, b"", f"{type(failed).__name__}: {getattr(failed, 'reason', failed)}"
    else:
        broke = ""
    if broke:
        raise ExhibitError(
            f"{record_id}: the exhibit door could not be reached ({broke}). Nothing is spent by asking, "
            "so asking again is safe",
            record_id=record_id,
        )
    if status != 200:
        kind = ExhibitNotReady if status == 409 else ExportKeyRefused if status == 401 else ExhibitError
        raise kind(
            f"{record_id}: the exhibit door answered {status}: {transport.said_in(body)}",
            record_id=record_id,
            status=status,
        )
    if len(body) > MAX_EXHIBIT:
        raise ExhibitError(
            f"{record_id}: the answer is larger than {MAX_EXHIBIT} bytes, which no exhibit is",
            record_id=record_id,
            status=status,
        )
    return body


def unpacked(data: bytes) -> dict[str, bytes]:
    """The three files, by name, from a zip that holds one folder of exactly those three."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ExhibitError("what the link handed over is not a zip; the link is spent") from None
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if (
        len({name.split("/", 1)[0] for name in names}) != 1
        or not all(_ENTRY.fullmatch(name) for name in names)
        or sorted(name.split("/", 1)[1] for name in names) != list(FILES)
    ):
        raise ExhibitError(f"the zip holds {names}, not one folder of {', '.join(FILES)}; the link is spent")
    files: dict[str, bytes] = {}
    for info in infos:
        try:
            with archive.open(info) as member:
                body: bytes | None = member.read(MAX_EXHIBIT + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError, zlib.error):
            body = None
        if body is None:
            raise ExhibitError(f"{info.filename} cannot be unpacked (damaged, encrypted, or packed in a way "
                               "this package does not read); the link is spent, ask for a new one")
        if len(body) > MAX_EXHIBIT:
            raise ExhibitError(f"{info.filename} unpacks to more than {MAX_EXHIBIT} bytes; the link is spent")
        files[info.filename.split("/", 1)[1]] = body
    return files


@dataclass(frozen=True)
class Held:
    """What an exhibit says about its record: enough to hold it to what was sent and what was answered."""

    record: Record
    leaf_index: int

    @property
    def record_hash(self) -> str:
        return self.record.record_hash_address()


def held_in(evidence: bytes) -> Held:
    """The record an exhibit is of, read from its ``evidence.json`` (a bundle, or a court export of one)."""
    try:
        document: Any = load_document(evidence)
        bundle = document.get("bundle", document)
        record = Record.model_validate(bundle["record"])
        leaf = bundle["leaf_index"]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ExhibitError("this package cannot read a record from evidence.json, so it files nothing") from None
    if not isinstance(leaf, int) or isinstance(leaf, bool) or not is_content_address(record.payload_hash):
        raise ExhibitError("evidence.json names no leaf, or its record commits to no address")
    return Held(record, leaf)


def what_differs(held: Held, sent: dict[str, Any]) -> list[str]:
    """Where the exhibit's record says something the line this directory sent did not.

    Every field the line stated must be in the record as stated, the fields it left out must be absent
    (or, for the time, filled in by the door), the event type must be the one the line's ``action_type``
    makes it, and the record must claim no capture tier: a record handed over was observed by nobody.
    The deployment's own fields (which agent, which version, whose deployment, which retention class)
    are the door's to state and are not held to the line. ``anchor_receipt`` and
    ``certification_pointer`` stand outside the record's hash and the door never writes them: an exhibit
    that carries either was changed after it was sealed, by somebody who is not the door.
    """
    record = held.record
    differs = [
        name
        for name in ("record_id", "payload_hash", "action_type", "actor_authority")
        if getattr(record, name) != sent.get(name)
    ]
    if "timestamp" in sent and record.timestamp != sent["timestamp"]:
        differs.append("timestamp")
    if record.event_type.value != ("ACTION_TRIGGERED" if sent.get("action_type") else "CONTEXT_RECEIVED"):
        differs.append("event_type")
    tiers = record.gap_manifest
    if tiers.tier1_runtime_hooks or tiers.tier2_transport_bytes or tiers.tier3_mcp_proxy:
        differs.append("gap_manifest")
    differs += [name for name in ("anchor_receipt", "certification_pointer") if getattr(record, name) is not None]
    return differs
