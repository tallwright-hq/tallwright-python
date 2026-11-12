# SPDX-License-Identifier: Apache-2.0
"""tallwright_cloud — Cloud Proof from Python, with the content kept where it is.

    from tallwright_cloud import Tallwright

    client = Tallwright(ingest_url, archive_key, "./tallwright-evidence")
    client.submit("what the agent was told")                            # context it received
    client.submit({"slot": "2026-11-03T09:00"}, action_type="appointment.booked")   # an action it took

This package is the recorder: it commits, keeps the evidence, sends, sends again and reads the
receipt, and nothing built on it does any of that again (https://docs.tallwright.com/adapters). The content
never leaves the caller's machine: a salted address of it does, and the pair that opens the address is
kept in the caller's evidence store, in the form the public verifier reads. What the door answers is a
receipt — a confirmation, not a proof; the proof is the exhibit made once a witness has seen the log,
checked with the disclosure kept here.

- :class:`Tallwright` records into one Environment: ``capture`` waits for the receipt, ``submit``
  only for the evidence (``client.py``, ``sender.py``);
- :class:`Environments` gives each end customer its own client, evidence and key (``environments.py``);
- :class:`LocalEvidence` and :class:`S3Evidence` keep the evidence (``store.py``);
- :class:`Account` makes and keeps the Environments themselves, with an account key (``account.py``);
- :class:`Exhibits` takes the exhibit of a record, with an export key;
- ``tallwright-cloud`` is the command line (``cli.py``).

See https://docs.tallwright.com/http for the same contract over plain HTTP, and
https://docs.tallwright.com/python/guarantees for what 1.0 promises and the tests that hold it to that.
"""

from __future__ import annotations

from .account import Account, AccountError, Environment, EnvironmentExists, Made, Secret
from .client import Capture, Exhibits, Status, Tallwright
from .environments import Environments
from .errors import (
    AccountClosed,
    EvidenceError,
    ExhibitError,
    ExhibitNotReady,
    ExportKeyRefused,
    LinkSpent,
    LostByTheDoor,
    NotConfirmed,
    RecordIdConflict,
    Refused,
    TallwrightError,
    Unauthorized,
)
from .ids import gaps
from .receipt import Receipt
from .sender import Flushed
from .store import EvidenceStore, LocalEvidence, S3Evidence

__version__ = "1.0.0rc1"

__all__ = [
    "Tallwright",
    "Environments",
    "Exhibits",
    "Account",
    "Capture",
    "Receipt",
    "Status",
    "Flushed",
    "EvidenceStore",
    "LocalEvidence",
    "S3Evidence",
    "Environment",
    "Made",
    "Secret",
    "gaps",
    "TallwrightError",
    "NotConfirmed",
    "Unauthorized",
    "AccountClosed",
    "Refused",
    "RecordIdConflict",
    "LostByTheDoor",
    "EvidenceError",
    "ExhibitError",
    "ExhibitNotReady",
    "LinkSpent",
    "ExportKeyRefused",
    "AccountError",
    "EnvironmentExists",
]
