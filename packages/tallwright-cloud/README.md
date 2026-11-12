# tallwright-cloud

Cloud Proof from Python. The content stays on your machine; a salted address of it is recorded.

This package is the recorder. It commits to the content, keeps the evidence, sends, sends again and
reads the receipt. Call it from your agent's code at the points where the agent acts; do not compute
a salt or a hash of your own beside it, because a second implementation of the evidence is the one a
court would then be asked to trust. What the package promises, and the test that holds each promise,
is in [its specification](https://docs.tallwright.com/python/guarantees).

```python
import os

from tallwright_cloud import Tallwright

client = Tallwright(
    "https://ingest.tallwright.com/<your book>",   # the ingest address your backoffice shows
    os.environ["TALLWRIGHT_KEY"],                  # the environment's key, shown once; keep it a secret
    "./tallwright-evidence",                       # where the pairs that open your records are kept
)
client.submit({"slot": "2026-11-03T09:00", "service": "haircut"}, action_type="appointment.booked")
```

## Two ways to record

- `client.submit(content, …)` returns once the evidence is safe on your side, and sends in the
  background: several records to a request, in order, the same bytes again for as long as the door's
  answer decides nothing. For an agent that must not wait on the network: a voice agent in the middle
  of a sentence. `client.flush()` waits for what was submitted; `client.close()` flushes and ends the
  sending thread; `client.status()` says what is queued and whether sending stopped.
- `client.capture(content, …)` waits for the door's receipt and raises when it does not come. For an
  action that must not run unrecorded.

`await client.asubmit(…)` and `await client.acapture(…)` do the same from a coroutine without holding
up its event loop. Both ways commit, write and read the door's answer through the same code.

Problems the background sending meets go to the `tallwright_cloud` logger, and to
`Tallwright(…, on_problem=callback)`, by type and record name and never with content: once per
streak of failures, not once per attempt. A key the door does not hold (401), a closed account (403)
or a redirect stops sending for that client; every record stays pending until a person acts:
`client.resend_pending()` once the key or the account is right again.

## What leaves your machine, and what does not

| Sent to Tallwright | Kept by you, in the evidence |
|---|---|
| `payload_hash`: the address of `salt ‖ content` | the content |
| `record_id` | the 32-byte salt |
| `action_type`, `actor_authority`, `timestamp` when you give them | `disclosure.json`: both, in the form the public verifier reads |

`record_id`, `action_type`, `actor_authority` and `timestamp` travel in the clear and are sealed into
every exhibit. Name events, kinds and rules in them, never people: the client refuses a space or an
`@` in the two named fields, which catches the easy mistakes and not all of them.

## Evidence that outlives the process

The evidence is the only copy of the content and of the salt that opens its address. Lose it and the
record can never be opened again, by anybody.

- A directory (`LocalEvidence`, or a path): on Linux the client refuses, by default, a directory on a
  file system that ends with its container (`overlay`, `tmpfs` and their kind), because a pod or a
  serverless instance loses it on its next restart. Put it on a volume that outlives the process.
- A bucket of anything that speaks S3 (`S3Evidence`), through an S3 client you make, so this package
  depends on no SDK of anybody's:

  ```python
  import boto3
  from tallwright_cloud import S3Evidence, Tallwright

  evidence = S3Evidence(boto3.client("s3"), "acme-evidence", prefix="tallwright")
  client = Tallwright(ingest_url, key, evidence)
  ```

  Every object is created only if absent (`If-None-Match: *`), so nothing is ever replaced; a botocore
  older than S3's conditional writes (August 2024) cannot send that, and is refused when the store is
  made. A bucket that ignores the condition would replace a salt without a word: `evidence.check()` and
  `tallwright-cloud doctor` write a probe twice and report it, and report credentials without
  `s3:ListBucket`, without which a record still to be sent cannot be found. Encryption at rest,
  versioning, object lock and who may read the bucket are yours to set.

Nothing is ever overwritten, in either store. A record pending under one key is never sent with
another: two Environments whose evidence was pointed at one place by mistake each send only their
own. After a key was replaced for the same Environment, `client.resend(record_id, adopt=True)` sends
a record that was pending under the old one.

## Many end customers

One Environment per end customer, each with its own key and its own evidence, all through one
sending thread:

```python
from tallwright_cloud import Environments

environments = Environments(ingest_url, key_for=lambda customer: vault.read(customer), evidence=evidence)
environments.client("4711").submit(content, action_type="callback.promised")
```

`key_for(customer_ref)` is yours: it returns the key of the Environment made for that customer, and
nothing on this side can tell two customers' keys apart before the door answers. Each customer's
evidence lives beneath its `customer_ref`, which is therefore a folder name every system takes: up to
100 of the characters `[a-z0-9._-]`, lower case so that no two customers share a folder on Windows or macOS.
`account.create` refuses any other before it makes anything.

Environments themselves are made by your system with an account key (`ta_…`, made by an Owner or
Admin on the Settings screen), never in the process that records:

```python
from tallwright_cloud import Account

account = Account("https://app.tallwright.com", os.environ["TALLWRIGHT_ACCOUNT_KEY"])
made = account.create("Bäckerei Müller", customer_ref="4711", deployer_label="acme-voice")
vault.write("4711", made.key.reveal())     # shown once, here and nowhere else
```

`customer_ref` is required, so a repeated create makes nothing twice. When an answer was lost on its
way back and the same call tried again, the 409 it meets says so (`EnvironmentExists.maybe_ours`); a
create you issue again later is a new call and says `maybe_ours` false. Either way,
`account.new_key(error.environment.id)` gives the Environment a key you hold. `account.find`,
`account.environments`, `account.close` do what their names say.

## What a capture is, and what it is not

A receipt is the door's confirmation that it holds the record: the leaf it sits at, its hash, the time
and who set it. It is **not a proof**, in the door's own words: no witness has seen the record until an
anchor covers its leaf, and the proof is the exhibit made after that, checked with the public verifier
and the disclosure kept here. Integrity of what was recorded, not completeness of what happened: a
record exists for what your code captured, and for nothing else.

## When the answer does not come

The pair, the outbox marker and the line are written, each durable, before anything is sent. If the
answer is lost, the same bytes are sent again; a record the door already holds is recognised by its
`record_id`, never written twice. When no receipt comes at all, `capture` raises `NotConfirmed` and the
record stays **pending**: `client.pending()` lists it, `client.resend(record_id)` sends the same line
again, and the next client to send in the background on the same evidence sends it on its own.

`Refused` means the door read the line and refused what it says, in its own sentence: the same line
will never be accepted. `RecordIdConflict` (409) means the door holds a different record under this
name; on a resend, whether that is an earlier send of this very line cannot be told from the answer,
and the message says so. An answer without the door's sentence, such as a proxy's error page, is never
taken for a refusal: the record stays pending.

Do not wrap `capture` in a retry loop of your own. After `NotConfirmed`, `resend`: a new capture is a
new record with a new salt, and an answer that was only lost becomes the same event recorded twice.

A receipt can also show that the door lost records it had confirmed: it puts a new record after the
record one of them followed, as a door's log does once it was put back to an earlier state and written
on. Those records are pending again, with the receipt that no longer stands kept beside them, and
`LostByTheDoor` names them to the logger and to `on_problem`; `resend` records each anew from the line
and the pair you kept.

## The exhibit

```python
filed = client.save_exhibit(link)  # the one-time link the backoffice gives; files <record_id>/exhibit/
```

The exhibit is filed only if it is of a record this evidence sent and says what its line said: the
same address, action, authority and stated time, and no capture tier claimed. Where the receipt was
kept, it must also name the receipt's leaf, record hash and time. `ExhibitNotReady` (409) means the door
could not build it yet, most often because no witness has covered the record; the link was not used.
`Exhibits(exhibits_url, export_key, evidence).save(record_id)` takes it with an export key instead,
kept where the exhibits are wanted and not where the agent runs. Checking the exhibit is the public
verifier's job, `evidence-verify`, which this package does not install: the Verifier screen of the
backoffice says how to get it. Then, offline, in the record's folder:
`evidence-verify exhibit/evidence.json --policy exhibit/policy.json --disclosure disclosure.json`.
Its first answer is 3, `bundle: NOT VERIFIED` with `integrity: VERIFIED`: everything holds, and the
reference time and the timestamp authority are the reader's to choose, not ours. `exhibit/our-claims.json`
proposes both; a reader who accepts them writes its `as_of` and `tsa_anchor` values into a copy of the
policy, checks again, and the answer is 0, `bundle: VALID`. A disclosure with one byte of the content
changed answers 1, `bundle: INVALID`. The lines that do all three are in
[Cloud Proof over HTTP](https://docs.tallwright.com/http#6-your-first-proof-end-to-end).

## The command line

```
tallwright-cloud doctor [--check-key]   what stands between this machine and evidence somebody can check
tallwright-cloud pending [--all-keys]   records sent and never confirmed or refused
tallwright-cloud resend [ID …]          send pending records again, byte for byte
tallwright-cloud gaps                   numbers missing from a session's sequence
tallwright-cloud export ID DIR          copy one record's evidence into a folder, for the verifier
```

The ingest address, the evidence and the key come from `TALLWRIGHT_INGEST`, `TALLWRIGHT_EVIDENCE`
and `TALLWRIGHT_KEY`. The key is never an argument: an argument is visible to every user of the
machine. Evidence in a bucket is `s3://bucket/prefix`, read with boto3 when it is installed.

## Numbered without a hole

Without a `record_id` of your own, records are named `<session>.<number>`, counting up from 000001
for each client in each process (a forked worker draws a session of its own). The name is sealed into
the record, so `gaps(record_ids)` can list the numbers missing below the highest one a session
reached. A hole is a capture that was numbered and is not in the log. No sequence can show a missing
tail, a session that sent nothing, or an action nothing captured.

## Keeping it safe

- The content, the salt and the key are kept out of this package's messages, logs and reprs, and out
  of the local variables of its frames, so an error tracker that records local variables records
  none of them from here. Your own code's frames are yours.
- The key travels over https only (plain http to a door on this machine), as a header no redirect
  carries, under this package's own certificate check. Proxies from the environment apply to other
  hosts and never to a door on this machine.
- An exhibit link and an export key are credentials: keep them out of logs and traces.
- On POSIX the evidence folders are 0700 and the files 0600. On Windows they take the permissions of
  the folder they are made in, so make the evidence directory where only the agent's account can read.

For a language without an SDK, the same contract over plain HTTP is
[Cloud Proof over HTTP](https://docs.tallwright.com/http); code that follows it does what this package does,
and its author answers for doing it exactly as written there.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the
license text and the NOTICE. It requires `tallwright-core`, which is under the same license. Installing it
also brings what `tallwright-core` requires, `pydantic` 2 and `rfc8785` with what those require, each
under its own license.
