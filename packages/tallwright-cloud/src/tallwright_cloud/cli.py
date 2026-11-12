# SPDX-License-Identifier: Apache-2.0
"""``tallwright-cloud``: look at the evidence and the door from a shell, and act on what is pending.

    tallwright-cloud doctor             what stands between this machine and evidence somebody can check
    tallwright-cloud pending            records sent and never confirmed or refused
    tallwright-cloud resend [ID ...]    send pending records again, byte for byte (all of this key's when none is named)
    tallwright-cloud gaps               numbers missing from a session's sequence
    tallwright-cloud export ID DIR      copy one record's evidence into a folder, for the verifier

The ingest address, the evidence and the key come from ``TALLWRIGHT_INGEST``, ``TALLWRIGHT_EVIDENCE``
and ``TALLWRIGHT_KEY``, or ``--ingest`` and ``--evidence``. The key is never an argument: an argument is
visible to every user of the machine in its process list. Evidence in a bucket is
``s3://bucket/prefix``, read with boto3 and its usual configuration, when boto3 is installed.

The commands read the evidence a client kept and make none: a directory that is not there is said to
be missing, never created and reported empty. One Environment's evidence is what they read; the store
``Environments`` writes into holds each customer's beneath its ``customer_ref``, and is said to be one.

Exit codes: 0 nothing stands in the way; 1 something does, and the output says what; 2 the command
itself was wrong.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import transport
from .client import Tallwright
from .errors import TallwrightError
from .evidence import DISCLOSURE, LINE, RECEIPT, REFUSED, Evidence
from .ids import checked_record_id, gaps
from .store import EvidenceStore, LocalEvidence, S3Evidence, _exclusive, walk

#: The interpreters this package is tested on, in order: its classifiers, and the CI's.
SUPPORTED = ((3, 11), (3, 12), (3, 13))


def _store(where: str | None, *, ephemeral_ok: bool = False) -> EvidenceStore:
    """The evidence at ``where``, opened as it is: a directory that is not there is not made."""
    if not where:
        raise SystemExit("tallwright-cloud: no evidence: --evidence or TALLWRIGHT_EVIDENCE")
    if where.startswith("s3://"):
        bucket, _, prefix = where[len("s3://") :].partition("/")
        try:
            import boto3  # noqa: PLC0415 - optional, the integrator's
        except ImportError:
            raise SystemExit("tallwright-cloud: evidence in a bucket is read with boto3, which is not installed") from None
        return S3Evidence(boto3.client("s3"), bucket, prefix=prefix)
    if not Path(where).is_dir():
        raise FileNotFoundError(
            f"no evidence directory at {where}: a client makes it when it is made with this path, and these "
            "commands only read what one kept. Is it the path the client was given?"
        )
    return LocalEvidence(where, ephemeral_ok=ephemeral_ok)


def _is_record(store: EvidenceStore, name: str) -> bool:
    """Whether ``name`` is a record's folder: the SDK writes a disclosure and a line into nothing else."""
    try:
        return store.read(f"{name}/{DISCLOSURE}") is not None or store.read(f"{name}/{LINE}") is not None
    except ValueError:  # not a name a record could be kept under
        return False


def _a_customer(store: EvidenceStore) -> str | None:
    """A ``customer_ref`` whose evidence lies in ``store``, when the store holds customers and not records.

    The first folder at the top that is either decides: a record, and this is one Environment's
    evidence; a folder whose first entry is a record, and this is the store ``Environments`` writes
    into, one folder per customer. Anything else is looked past.
    """
    for top in Evidence(store).records():
        if _is_record(store, top):
            return None
        inside = [name for name in store.children(top) if not name.startswith(".")]
        if inside and _is_record(store, f"{top}/{inside[0]}"):
            return top
    return None


def _records(store: EvidenceStore) -> Evidence:
    """One Environment's evidence in ``store``; refused, with the folder to name instead, for every customer's."""
    customer = _a_customer(store)
    if customer is not None:
        raise ValueError(
            f"{store.locate('')} holds each customer's evidence beneath its customer_ref, not records: "
            f"one customer's is --evidence {store.locate(customer)}"
        )
    return Evidence(store)


def _key() -> str:
    key = os.environ.get("TALLWRIGHT_KEY", "")
    if not key:
        raise SystemExit("tallwright-cloud: no key: set TALLWRIGHT_KEY (never an argument)")
    return key


def _client(args: argparse.Namespace) -> Tallwright:
    if not args.ingest:
        raise SystemExit("tallwright-cloud: no ingest address: --ingest or TALLWRIGHT_INGEST")
    return Tallwright(args.ingest, _key(), _records(_store(args.evidence, ephemeral_ok=args.ephemeral_ok)).store)


def _say(line: str) -> None:
    print(line)  # noqa: T201


def doctor(args: argparse.Namespace) -> int:
    trouble = 0
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if (sys.version_info.major, sys.version_info.minor) in SUPPORTED:
        _say(f"ok      Python {running}")
    else:  # a note, not a problem: the checks below run on this interpreter and say whether it is in the way
        lowest, highest = (".".join(map(str, version)) for version in (SUPPORTED[0], SUPPORTED[-1]))
        _say(f"note    Python {running}: this package is tested on {lowest} to {highest}, not on this one")
    try:
        store = _store(args.evidence, ephemeral_ok=args.ephemeral_ok)
        problems = store.check()
    except (OSError, ValueError) as failed:
        problems = [str(failed)]
        store = None
    for problem in problems:
        trouble += 1
        _say(f"PROBLEM evidence: {problem}")
    if store is not None and not problems:
        _say(f"ok      evidence at {store.locate('')} keeps what it is given and never replaces it")
        customer = _a_customer(store)
        if customer is not None:
            _say(
                f"note    {store.locate('')} holds each customer's evidence beneath its customer_ref: what "
                f"is pending is counted for one customer, with --evidence {store.locate(customer)}"
            )
        else:
            pending = Evidence(store).pending()
            _say(f"{'ok     ' if not pending else 'note   '} {len(pending)} record(s) pending in the evidence")
    if not args.ingest:
        trouble += 1
        _say("PROBLEM no ingest address: --ingest or TALLWRIGHT_INGEST")
        return 1
    try:
        endpoint = transport.endpoint(args.ingest)
    except ValueError as wrong:
        _say(f"PROBLEM ingest address: {wrong}")
        return 1
    try:
        status, _ = transport.fetch(args.ingest.rstrip("/") + "/healthz", args.timeout, 4096)
    except OSError as failed:
        trouble += 1
        _say(f"PROBLEM the door at {args.ingest} cannot be reached: {type(failed).__name__}: {getattr(failed, 'reason', failed)}")
        return 1
    if status == 200:
        _say(f"ok      the door at {args.ingest} answers, over a certificate this machine trusts")
    else:
        trouble += 1
        _say(f"PROBLEM the door at {args.ingest} answered its liveness probe with {status}")
    if args.check_key:
        try:
            answer = transport.post(endpoint, transport.Key(_key()), b"", args.timeout)
        except (OSError, ValueError) as failed:
            trouble += 1
            _say(f"PROBLEM the key could not be checked: {type(failed).__name__}: {getattr(failed, 'reason', failed)}")
        else:
            if answer.status == 200:
                _say("ok      the door holds this key (an empty batch was sent: nothing was recorded)")
            else:
                trouble += 1
                _say(f"PROBLEM the door answered an empty batch with {answer.status}: {transport.said(answer) or 'no sentence'}")
    return 1 if trouble else 0


def pending(args: argparse.Namespace) -> int:
    evidence = _records(_store(args.evidence, ephemeral_ok=args.ephemeral_ok))
    names = evidence.pending() if args.all_keys or not os.environ.get("TALLWRIGHT_KEY") else evidence.pending(transport.Key(_key()).binding())
    for name in names:
        _say(name)
    return 0


def resend(args: argparse.Namespace) -> int:
    if args.adopt and not args.record_ids:
        _say(
            "tallwright-cloud resend --adopt: name each record to send with this key. Whether a record "
            "pending under another key is this Environment's is yours to know, record by record; "
            "tallwright-cloud pending --all-keys lists them"
        )
        return 2
    client = _client(args)
    names = args.record_ids or client.pending()
    others = [] if args.record_ids else sorted(set(Evidence(client.evidence).pending()) - set(names))
    failed = 0
    for name in names:
        try:
            captured = client.resend(name, adopt=args.adopt)
        except TallwrightError as problem:
            failed += 1
            _say(f"{name}: {type(problem).__name__}: {problem}")
        else:
            _say(f"{name}: {captured.receipt.status} at leaf {captured.receipt.leaf_index}")
    if not names:
        _say("nothing pending under this key")
    if others:
        _say(
            f"{len(others)} record(s) pending under another key, not sent with this one: tallwright-cloud "
            "pending --all-keys lists them, and if this key replaced that one for the same Environment, "
            "tallwright-cloud resend --adopt ID sends each"
        )
    return 1 if failed or others else 0


def _short_of_the_log(store: EvidenceStore, name: str) -> str:
    """Why the log is not shown to hold a record kept here, or "" when its receipt is kept."""
    if store.read(f"{name}/{RECEIPT}") is not None:
        return ""
    if store.read(f"{name}/{REFUSED}") is not None:
        return "refused"
    return "pending" if store.read(f"{name}/{LINE}") is not None else "never sent"


def show_gaps(args: argparse.Namespace) -> int:
    # A hole is a capture that was numbered and is not in the log. What shows a record in the log here
    # is its receipt, so a number is a hole when no record of it is kept, and when the record kept was
    # refused, is pending or was never sent; each is said as what it is.
    evidence = _records(_store(args.evidence, ephemeral_ok=args.ephemeral_ok))
    kept = evidence.records()
    found = {session: dict.fromkeys(missing, "") for session, missing in gaps(kept).items()}
    for name in kept:
        for session in gaps([name]):  # once for a name this client minted, <session>.<number>
            if short := _short_of_the_log(evidence.store, name):
                found[session][int(name.rpartition(".")[2])] = short
    holes = 0
    for session, missing in sorted(found.items()):
        if missing:
            holes += len(missing)
            shown = ", ".join(f"{n} ({missing[n]})" if missing[n] else str(n) for n in sorted(missing)[:20])
            _say(f"{session}: {len(missing)} missing: {shown}{' …' if len(missing) > 20 else ''}")
    if holes:
        _say(
            "missing: not in the log as far as this evidence shows. A bare number has no record here; "
            "(refused) the door refused it; (pending) the door has not confirmed it, and resend sends it "
            "again; (never sent) only its pair was kept"
        )
    else:
        _say(
            "no hole: up to the highest number of every session, each record's receipt is kept here "
            "(which says nothing about what was never captured)"
        )
    return 1 if holes else 0


def _folders(folder: Path) -> None:
    """``folder`` and each folder above it that is missing, made the owner's alone (0700), as in the store."""
    missing = []
    while not folder.exists():
        missing.append(folder)
        folder = folder.parent
    for made in reversed(missing):
        made.mkdir(mode=0o700, exist_ok=True)


def export(args: argparse.Namespace) -> int:
    store = _records(_store(args.evidence, ephemeral_ok=args.ephemeral_ok)).store
    name = checked_record_id(args.record_id)
    if not _is_record(store, name):
        _say(f"{name}: no such record in {store.locate('')}")
        return 1
    target = Path(args.to)
    copied, disclosed = 0, False
    for inside in walk(store, name):
        out = target.joinpath(*inside.split("/")[1:])
        _folders(out.parent)
        # The content and the salt, kept as the store keeps them: the owner's alone (0600), and never
        # over a file already there. Sharing the copy is a person's act, done on purpose.
        with os.fdopen(_exclusive(out), "wb") as written:
            written.write(store.read(inside) or b"")
        copied += 1
        disclosed = disclosed or inside == f"{name}/{DISCLOSURE}"
    opened = (
        f"evidence-verify reads the disclosure at {target / DISCLOSURE}"
        if disclosed
        else f"it holds no {DISCLOSURE}, so nobody can open what it commits to"
    )
    _say(f"{name}: {copied} file(s) in {target}; {opened}")
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    common: dict[str, Any] = {}
    sub = top.add_subparsers(dest="command", required=True)
    for name, run, help_ in (
        ("doctor", doctor, "what stands between this machine and evidence somebody can check"),
        ("pending", pending, "records sent and never confirmed or refused"),
        ("resend", resend, "send pending records again, byte for byte"),
        ("gaps", show_gaps, "numbers missing from a session's sequence"),
        ("export", export, "copy one record's evidence into a folder"),
    ):
        command = sub.add_parser(name, help=help_, **common)
        command.set_defaults(run=run)
        command.add_argument("--evidence", default=os.environ.get("TALLWRIGHT_EVIDENCE"))
        command.add_argument("--ephemeral-ok", action="store_true", help="accept evidence on a file system that ends with its container")
        if name in ("doctor", "resend"):
            command.add_argument("--ingest", default=os.environ.get("TALLWRIGHT_INGEST"))
        if name == "doctor":
            command.add_argument("--timeout", type=float, default=10.0)
            command.add_argument("--check-key", action="store_true", help="send an empty batch to check the key; records nothing")
        if name == "pending":
            command.add_argument("--all-keys", action="store_true", help="also records pending under another key")
        if name == "resend":
            command.add_argument("record_ids", nargs="*")
            command.add_argument("--adopt", action="store_true", help="send the records named, pending under a replaced key, with this one")
        if name == "export":
            command.add_argument("record_id")
            command.add_argument("to")
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.run(args))
    except (TallwrightError, OSError, ValueError) as failed:
        _say(f"tallwright-cloud: {type(failed).__name__}: {failed}")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
