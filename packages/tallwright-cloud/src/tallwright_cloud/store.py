# SPDX-License-Identifier: Apache-2.0
"""Where the evidence is kept: a store that only ever adds, and says so when it cannot.

The evidence of a record is the one copy of the customer's content and of the salt that opens its
address (``evidence.py``). Lose it and the record can never be opened again, by anybody. So the SDK
asks one thing of a store, whatever it is built on, and holds every store to it:

**Create, never replace.** :meth:`EvidenceStore.create` writes a new object and is durable when it
returns; an object already under that name is refused (:class:`FileExistsError`), never overwritten,
so a second capture under a name cannot replace the salt of the first. Nothing the SDK keeps is ever
rewritten. The two things it removes are its own notes (``evidence.py``), which hold no evidence:
the outbox marker that a line is still to be sent, and the note of which record follows a record
hash, replaced when a receipt shows the door's log holds another one there.

**Durable before the door hears of it.** The SDK writes the disclosure and the line, and only then
sends; a store that returned before the bytes were safe would let a record reach the door whose salt
exists nowhere. A local store flushes the file and its folder, on macOS to the drive itself; an
object store is durable when its PUT is answered.

Two stores are built in:

- :class:`LocalEvidence`, a directory. On Linux it refuses, by default, a directory on a file system
  that disappears with its container (``overlay``, ``tmpfs`` and their kind): a pod or a serverless
  instance that keeps its evidence there loses it on its next restart, silently and for ever.
- :class:`S3Evidence`, a bucket of anything that speaks the S3 API, through a client the integrator
  makes (``boto3.client("s3")``), so this package depends on no SDK of anybody's. It needs conditional
  writes (``If-None-Match: *``) and credentials that may list the bucket; :meth:`S3Evidence.check`
  proves both, and ``tallwright-cloud doctor`` runs that check.
"""

from __future__ import annotations

import errno
import importlib
import os
import re
import secrets
import sys
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, runtime_checkable

#: A name inside a store: slash-separated parts, each a folder name every system takes. The SDK makes
#: them from record ids (``ids.checked_record_id``) and its own fixed names; nothing else reaches here.
_PART = re.compile(r"\.?[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

#: File systems whose contents end with the container, the instance or the boot they belong to.
EPHEMERAL = frozenset({"overlay", "overlayfs", "aufs", "tmpfs", "ramfs", "devtmpfs", "squashfs", "fuse.lxcfs"})


def checked_name(name: str) -> str:
    """``name``, if every part of it is a plain folder or file name; refused otherwise."""
    parts = name.split("/")
    if not name or any(not _PART.fullmatch(part) or part.endswith(".") or part in {".", ".."} for part in parts):
        raise ValueError(f"{name!r} is not a name inside an evidence store")
    return name


@runtime_checkable
class EvidenceStore(Protocol):
    """What the SDK needs of the place that keeps its evidence: create, never replace, and durable on return.

    Built in: :class:`LocalEvidence` (a directory) and :class:`S3Evidence` (a bucket).
    """

    def create(self, name: str, data: bytes) -> None:
        """Write a new object, durable on return. :class:`FileExistsError` if ``name`` is taken."""

    def read(self, name: str) -> bytes | None:
        """The object's bytes, or None when there is none under ``name``."""

    def children(self, prefix: str) -> list[str]:
        """The names one level below ``prefix`` (``""`` is the top), files and folders alike, sorted."""

    def remove(self, name: str) -> None:
        """Remove an outbox marker, a chain note or a probe. Never called on evidence."""

    def within(self, part: str) -> EvidenceStore:
        """The same store, beneath ``part``: one Environment's evidence apart from another's."""

    def locate(self, name: str) -> str:
        """Where ``name`` is, for a person: a path, or an ``s3://`` address; ``""`` is the store itself."""

    def check(self) -> list[str]:
        """What stands in the way of this store keeping evidence; empty when nothing does."""


# --- a directory ----------------------------------------------------------------------------------

#: ``fcntl``, where there is one. Its ``F_FULLFSYNC`` is macOS's alone.
_fcntl: Any = None if sys.platform == "win32" else importlib.import_module("fcntl")
#: What a file system that does not take ``F_FULLFSYNC`` answers it with (some network ones).
_NO_FULL_SYNC = frozenset({errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL, errno.ENOTTY})


def _durable(handle: int) -> None:
    """Make what was written through ``handle`` durable.

    On macOS ``fsync`` only hands the bytes to the drive, which may keep them in its cache and write
    them later, and out of order (Apple's fsync(2)): a power cut after the line was sent could still
    take the disclosure. ``F_FULLFSYNC`` has the drive write them. A file system that does not take it
    has had ``fsync``, which is all it offers; a drive that fails it fails the write.
    """
    os.fsync(handle)
    full = getattr(_fcntl, "F_FULLFSYNC", None)
    if full is None:
        return
    try:
        _fcntl.fcntl(handle, full)
    except OSError as failed:
        if failed.errno not in _NO_FULL_SYNC:
            raise


def _sync_folder(folder: Path) -> None:  # pragma: no cover - one arm per platform
    """Make a new name in ``folder`` durable. Windows has no directory handle to flush."""
    if sys.platform == "win32":
        return
    handle = os.open(folder, os.O_RDONLY)
    try:
        _durable(handle)
    finally:
        os.close(handle)


def _exclusive(path: Path) -> int:
    """A new file the owner alone can read; refused if anything is already at ``path``."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)


def _write(handle: int, data: bytes) -> None:
    with os.fdopen(handle, "wb") as written:
        written.write(data)
        written.flush()
        _durable(written.fileno())


def _unescape(field: str) -> str:
    """A mount point as /proc/self/mountinfo writes it: a space is ``\\040``, a tab ``\\011``."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def filesystem_of(path: str | os.PathLike[str], mountinfo: str | None = None) -> str | None:
    """The type of the file system ``path`` is on, read from ``/proc/self/mountinfo``; None elsewhere.

    The longest mount point that contains the path wins, so a volume mounted into a container is its
    own file system, not the container's overlay.
    """
    if mountinfo is None:
        try:
            mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    target = PurePosixPath(Path(path).as_posix())
    best: tuple[int, str] | None = None
    for line in mountinfo.splitlines():
        before, sep, after = line.partition(" - ")
        fields = before.split()
        if not sep or len(fields) < 5 or not after.split():
            continue
        point = PurePosixPath(_unescape(fields[4]))
        if target == point or point in target.parents:
            depth = len(point.parts)
            if best is None or depth >= best[0]:
                best = (depth, after.split()[0])
    return best[1] if best else None


class LocalEvidence:
    """Evidence in a directory: one folder per record, the owner's alone on POSIX (0700, files 0600).

    ``ephemeral_ok`` is for a directory that is meant to end with the process: a test, a demo. Left
    False, a directory on a file system that ends with its container is refused, because a record whose
    evidence is gone can never be opened again (see :data:`EPHEMERAL`).
    """

    def __init__(self, root: str | os.PathLike[str], *, ephemeral_ok: bool = False) -> None:
        self.root = Path(root)
        self.ephemeral_ok = ephemeral_ok
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not ephemeral_ok and (problems := self._ephemeral()):
            raise OSError(problems[0])

    def __repr__(self) -> str:
        return f"LocalEvidence({str(self.root)!r})"

    def _ephemeral(self) -> list[str]:
        kind = filesystem_of(self.root.resolve())
        if kind in EPHEMERAL:
            return [
                f"{self.root} is on a {kind} file system, which ends with the container or the machine's "
                "next boot, and every record's evidence with it. Keep it on a volume that outlives the "
                "process, or in an object store (S3Evidence); a directory meant to end with the process "
                "(a test, a demo) is LocalEvidence(path, ephemeral_ok=True)"
            ]
        return []

    def path(self, name: str) -> Path:
        """Where ``name`` is on disk, once the name is checked: a name cannot lead out of the evidence directory."""
        return self.root.joinpath(*checked_name(name).split("/"))

    def create(self, name: str, data: bytes) -> None:
        target = self.path(name)
        made = []
        folder = target.parent
        while not folder.exists():
            made.append(folder)
            folder = folder.parent
        for folder in reversed(made):
            try:
                folder.mkdir(mode=0o700)
            except FileExistsError:
                pass
        # Written beside the name and linked into it: a link fails when the name exists, so creating
        # stays exclusive, and nobody ever reads a half-written object under its own name. A file
        # system without links (FAT, some network shares) is written in place, exclusively.
        part = target.with_name(f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}.part")
        try:
            _write(_exclusive(part), data)
            try:
                os.link(part, target)
            except FileExistsError:
                raise
            except OSError:  # pragma: no cover - a file system without hard links
                _write(_exclusive(target), data)
        finally:
            part.unlink(missing_ok=True)
        # The new name, and every folder made for it, durable in the folder that holds it.
        for folder in {target.parent, *(made_one.parent for made_one in made)}:
            _sync_folder(folder)

    def read(self, name: str) -> bytes | None:
        target = self.path(name)
        if not target.is_file():
            return None
        try:
            return target.read_bytes()
        except FileNotFoundError:
            return None

    def children(self, prefix: str) -> list[str]:
        folder = self.path(prefix) if prefix else self.root
        try:
            return sorted(entry.name for entry in folder.iterdir() if not entry.name.endswith(".part"))
        except (FileNotFoundError, NotADirectoryError):
            return []

    def remove(self, name: str) -> None:
        self.path(name).unlink(missing_ok=True)

    def within(self, part: str) -> LocalEvidence:
        return LocalEvidence(self.path(part), ephemeral_ok=self.ephemeral_ok)

    def locate(self, name: str) -> str:
        return str(self.path(name) if name else self.root)

    def check(self) -> list[str]:
        problems = [] if self.ephemeral_ok else self._ephemeral()
        probe = f".doctor/{secrets.token_hex(8)}"
        try:
            self.create(probe, b"probe")
            try:
                self.create(probe, b"again")
                problems.append(f"{self.root}: an object was replaced, so a salt could be overwritten")
            except FileExistsError:
                pass
        except OSError as failed:
            problems.append(f"{self.root} cannot be written ({failed.strerror or failed})")
        finally:
            self.remove(probe)
        return problems


# --- a bucket --------------------------------------------------------------------------------------


def _code(failed: BaseException) -> tuple[str, int | None]:
    """The S3 error code and HTTP status of a client's exception, as botocore and its kin carry them."""
    response: Any = getattr(failed, "response", None)
    if not isinstance(response, dict):
        return "", None
    error = response.get("Error") or {}
    meta = response.get("ResponseMetadata") or {}
    status = meta.get("HTTPStatusCode")
    return str(error.get("Code", "")), status if isinstance(status, int) else None


def _asked(call: Callable[..., Any], **asked: Any) -> tuple[Any, str, int | None]:
    """The client's answer and ``""``; or None, the error's code (its type, when it has none) and status.

    The client's exception ends here, so no error raised about it chains to it: its frames hold what
    was asked, and what is asked of a write is the object's bytes, a disclosure's salt and content.
    """
    try:
        return call(**asked), "", None
    except Exception as failed:  # noqa: BLE001 - every S3 client raises its own kinds
        code, status = _code(failed)
        return None, code or type(failed).__name__, status


def _sends_conditions(client: Any) -> bool:
    """Whether the client can send ``If-None-Match``. botocore knows it from the releases that came
    with S3's conditional writes (August 2024); a client without botocore's model of ``PutObject``
    (another library, a test's mock) is taken at its word, and :meth:`S3Evidence.check` proves it."""
    try:
        members = client.meta.service_model.operation_model("PutObject").input_shape.members
    except Exception:  # noqa: BLE001 - not botocore's
        return True
    return not isinstance(members, Mapping) or "IfNoneMatch" in members


#: What S3 and its kin answer for a name that holds nothing.
_NOT_THERE = ("NoSuchKey", "404", "NotFound")


class S3Evidence:
    """Evidence in a bucket, through an S3 client the integrator made and configured.

        import boto3
        evidence = S3Evidence(boto3.client("s3"), "acme-evidence", prefix="tallwright")

    Every object is written with ``IfNoneMatch="*"``, so an object already there is refused by the
    bucket rather than replaced, and a PUT that was answered is durable. A refusal of an object that
    holds exactly the bytes asked for is the client's own retry of a write that landed, and the write
    is done. A bucket or a service that ignores the condition would replace a salt without a word:
    :meth:`check` writes a probe twice and reports it, and nothing should record into a bucket that
    fails it. Encryption at rest, versioning, object lock and who may read the bucket are the bucket's
    settings, and the owner's to choose: this is the only copy of the content.
    """

    def __init__(self, client: Any, bucket: str, *, prefix: str = "") -> None:
        if not isinstance(bucket, str) or not bucket:
            raise ValueError("a bucket is named")
        if not _sends_conditions(client):
            raise ValueError(
                "this S3 client's botocore is older than S3's conditional writes (August 2024): it cannot "
                "send If-None-Match, so every evidence write would fail. Upgrade boto3, and botocore with it"
            )
        self.client = client
        self.bucket = bucket
        self.prefix = checked_name(prefix.strip("/")) + "/" if prefix.strip("/") else ""

    def __repr__(self) -> str:
        return f"S3Evidence(bucket={self.bucket!r}, prefix={self.prefix!r})"

    def _key(self, name: str) -> str:
        return self.prefix + checked_name(name)

    def _object(self, key: str) -> bytes:
        return bytes(self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read())

    def _get(self, name: str) -> tuple[bytes | None, str, int | None]:
        data, code, status = _asked(self._object, key=self._key(name))
        return data, code, status

    def create(self, name: str, data: bytes) -> None:
        _, code, status = _asked(self.client.put_object, Bucket=self.bucket, Key=self._key(name), Body=data, IfNoneMatch="*")
        if not code:
            return
        if code in ("PreconditionFailed", "ConditionalRequestConflict") or status in (409, 412):
            # Taken, or being taken: perhaps by this very write. A client whose first attempt landed and
            # whose answer was lost sends it again, and the bucket refuses the retry. An object holding
            # exactly these bytes refuses nothing this write asked for, and the bytes of a disclosure or
            # a line are no other write's, by their salt: it is this write, landed.
            kept, unread, _ = self._get(name)
            if not unread and kept == data:
                return
            raise FileExistsError(f"{self.locate(name)} exists already")
        if code == "NotImplemented" or status == 501:
            raise OSError(
                f"{self.locate(name)} could not be written (NotImplemented): the service does not do "
                "conditional writes (If-None-Match: *), and without them a salt could be replaced"
            )
        raise OSError(f"{self.locate(name)} could not be written ({code})")

    def read(self, name: str) -> bytes | None:
        data, code, status = self._get(name)
        if not code:
            return data
        if code in _NOT_THERE or status == 404:
            return None
        raise OSError(f"{self.locate(name)} could not be read ({code})")

    def children(self, prefix: str) -> list[str]:
        below = self.prefix + (checked_name(prefix) + "/" if prefix else "")
        found: set[str] = set()
        token: str | None = None
        while True:
            asked: dict[str, Any] = {"Bucket": self.bucket, "Prefix": below, "Delimiter": "/"}
            if token:
                asked["ContinuationToken"] = token
            page, code, _ = _asked(self.client.list_objects_v2, **asked)
            if code:
                raise OSError(f"{self.locate(prefix or '')} could not be listed ({code})")
            for common in page.get("CommonPrefixes") or []:
                found.add(str(common["Prefix"])[len(below) :].rstrip("/"))
            for item in page.get("Contents") or []:
                found.add(str(item["Key"])[len(below) :])
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
        return sorted(name for name in found if name)

    def remove(self, name: str) -> None:
        _, code, _ = _asked(self.client.delete_object, Bucket=self.bucket, Key=self._key(name))
        if code:
            raise OSError(f"{self.locate(name)} could not be removed ({code})")

    def within(self, part: str) -> S3Evidence:
        return S3Evidence(self.client, self.bucket, prefix=self.prefix + checked_name(part))

    def locate(self, name: str) -> str:
        return f"s3://{self.bucket}/{self.prefix}{checked_name(name) if name else ''}"

    def check(self) -> list[str]:
        problems: list[str] = []
        probe = f".doctor/{secrets.token_hex(8)}"
        try:
            self.create(probe, b"probe")
            try:
                self.create(probe, b"again")
                problems.append(
                    f"s3://{self.bucket}/{self.prefix}: the bucket replaced an object it was told to create "
                    "only if absent (If-None-Match: *). A salt there could be overwritten: do not record into it"
                )
            except FileExistsError:
                pass
            if self.read(probe) != b"probe":
                problems.append(f"s3://{self.bucket}/{self.prefix}: an object written was not read back as written")
            try:
                self.read(f"{probe}.absent")
                self.children(".doctor")
            except OSError as unlisted:
                problems.append(
                    f"{unlisted}: what is still to be sent is found by listing the bucket and reading names "
                    "that may not be there, and S3 answers both with AccessDenied to credentials without "
                    "s3:ListBucket on the bucket"
                )
        except OSError as failed:
            problems.append(str(failed))
        finally:
            try:
                self.remove(probe)
            except OSError:
                pass
        return problems


def store_of(evidence: str | os.PathLike[str] | EvidenceStore) -> EvidenceStore:
    """A store for what the caller passed: a store as it is, a path as a :class:`LocalEvidence`."""
    if isinstance(evidence, (str, os.PathLike)):
        return LocalEvidence(evidence)
    if isinstance(evidence, EvidenceStore):
        return evidence
    raise TypeError(f"evidence is a directory or an EvidenceStore, not {type(evidence).__name__}")


def walk(store: EvidenceStore, prefix: str = "") -> Iterator[str]:
    """Every object name below ``prefix``, depth first: what ``export`` copies. The store's own
    markers and probes (names that begin with a dot) are not evidence and are passed over."""
    for child in store.children(prefix):
        if child.startswith("."):
            continue
        name = f"{prefix}/{child}" if prefix else child
        if store.read(name) is not None:
            yield name
        else:
            yield from walk(store, name)
