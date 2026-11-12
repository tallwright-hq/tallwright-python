# tallwright-cloud 1.0 — what it promises, and what holds it to that

This is the requirement set of the Python Cloud SDK, version 1.0, and its test catalogue. Every
requirement has an ID; every ID is named by at least one test (`# covers: SDK-…`), and the
suite fails when one is not. A requirement nobody tests is a sentence, not a promise. The tests
run in Tallwright's own CI; they are not part of this release.

**What the SDK is.** The recorder. It commits to the content, keeps the evidence, sends, sends again
and reads the receipt. Adapters, connectors, examples, documentation and prompts decide when to call
it and with what; none of them does any of its work again ([the adapter contract](https://docs.tallwright.com/adapters)). An
integration that computes a salt or a hash of its own is a second implementation of the evidence.

**What it is not.** Proof that an event happened, that what was recorded was true, or that every
action was recorded. It proves that a record has not changed since the door took it, and what it
commits to, once a witness has covered it and the exhibit is checked with the disclosure kept here.

---

## 1. Requirements

### Commitment — `SDK-COM`

| ID | Requirement |
|---|---|
| SDK-COM-1 | Content is bytes, text (UTF-8) or a JSON object or array (RFC 8785). Anything else is refused before anything is written. |
| SDK-COM-2 | Every record has its own salt: 32 bytes from the operating system's random source, never reused and never derived. |
| SDK-COM-3 | The address is `"f1220"` and the lower-case hex SHA-256 of salt followed by content, as the exhibit format specifies. |
| SDK-COM-4 | Content and salt appear in no repr, no log line, no exception message and no local variable of a frame an exception leaves through. |
| SDK-COM-5 | A refusal of content names its type and why, never its value. |

### The line — `SDK-LINE`

| ID | Requirement |
|---|---|
| SDK-LINE-1 | The line is RFC 8785 JSON of `record_id`, `payload_hash` and, when given, `action_type`, `actor_authority`, `timestamp`. No other field is ever sent; never `payload`, `payload_b64` or `subject_id`. |
| SDK-LINE-2 | `action_type` and `actor_authority` are 1 to 128 of `A-Z a-z 0-9 . _ : / + -`, starting with a letter or a digit; anything else is refused without being repeated. |
| SDK-LINE-3 | `timestamp` is RFC 3339 with an offset, or absent. |
| SDK-LINE-4 | A minted name is `<session>.<number>`, numbered without a hole or a repeat, per process; a fork draws a new session. A caller's own `record_id` names a folder of its own on every system: lower case, so that no two are one folder where case is not told apart. Any other is refused by the rule it breaks, without being repeated. |

### Evidence — `SDK-EVD`

| ID | Requirement |
|---|---|
| SDK-EVD-1 | Write-ahead: the disclosure, the outbox marker and the line are durable, in that order, before anything is sent. |
| SDK-EVD-2 | Nothing is overwritten. A `record_id` already kept is refused before anything is sent. |
| SDK-EVD-3 | A pending line is sent again only while its disclosure opens its address. |
| SDK-EVD-4 | A process that ends at any point loses no disclosure of a record the door may hold, and no record is held twice. |
| SDK-EVD-5 | Evidence on a file system that ends with its container (`overlay`, `tmpfs` and their kind) is refused by default. |
| SDK-EVD-6 | Every store gives the same guarantees: a directory, and a bucket of anything that speaks S3 with conditional writes. A bucket that replaces what it was told to create only if absent is reported by `check()`. |
| SDK-EVD-7 | On POSIX, evidence folders are the owner's alone (0700) and its files too (0600). |
| SDK-EVD-8 | One record's evidence can be exported to a folder the public verifier reads. |
| SDK-EVD-9 | A record pending under one key is never sent with another, unless the caller adopts it. |
| SDK-EVD-10 | A receipt that puts another record after the record a kept receipt's record follows shows the door lost the kept one and those kept after it. They are reported by name (`LostByTheDoor`, to the logger and `on_problem`), noted beside their receipts with nothing removed, and pending again, so `resend` records them anew. Two Environments in one store never take each other's receipts back. |

### Sending — `SDK-SND`

| ID | Requirement |
|---|---|
| SDK-SND-1 | HTTPS only, except to a door on this machine; the package's own TLS context; no redirect followed; no proxy for a loopback door; the key never in a URL. |
| SDK-SND-2 | An answer that decides nothing (no answer, 408, 425, 429, 500, 502, 503, 504) is followed by the same bytes again; a record is never committed again for a retry. |
| SDK-SND-3 | Every answer means one thing, read in one place for one line and for many: 200 with a receipt confirms; 400 `line N is not a usable record` and 409 with the door's sentence refuse; 401 and 403 stop; 3xx stops without following; anything else is not confirmed. |
| SDK-SND-4 | A receipt is read strictly: a missing field, a wrong type, another record's name or another time is no receipt. |
| SDK-SND-5 | `submit` returns once the evidence is durable; a background sender delivers in order, several lines to a request, and `flush` waits for it. |
| SDK-SND-6 | What an earlier process left pending under the same key is sent again by the next client that sends in the background, or by `resend_pending`. |
| SDK-SND-7 | 401, 403 and a redirect stop sending for that client; its records stay pending and are reported. Other failures are tried again, each client backed off on its own: the wait doubles from half a second to a minute, give or take a fifth so that clients do not send at once, so at most 72 seconds between attempts. |
| SDK-SND-8 | Every request has a timeout, and no answer is read past 1 MiB. |
| SDK-SND-9 | An answer about several lines that is not a receipt for each is never guessed at: the lines are sent one by one. |

### Many Environments — `SDK-TEN`

| ID | Requirement |
|---|---|
| SDK-TEN-1 | `Environments` gives each `customer_ref` its own client, its own key from `key_for`, and its evidence beneath its own `customer_ref`. |
| SDK-TEN-2 | All clients of one `Environments` share one sending thread and take turns on it: neither one client's failures nor its load hold up another's records. |
| SDK-TEN-3 | A `customer_ref` names a folder of its own on every system, by a `record_id`'s rule, so that no two customers share one. Any other is refused without being repeated, by `Account.create` too, before anything is made. |

### The account — `SDK-ACC`

| ID | Requirement |
|---|---|
| SDK-ACC-1 | `Account.create` requires a `customer_ref`, so that a repeated create makes nothing twice; a 409 says whether an earlier attempt of the same call may have made it. |
| SDK-ACC-2 | A key the API returns is wrapped in a `Secret` whose repr shows its face only. |
| SDK-ACC-3 | `environments`, `find`, `new_key` and `close` do what the API does, page by page. |
| SDK-ACC-4 | The account key is never needed by the recording client, and the recording client never holds one. |

### Telling — `SDK-OBS`

| ID | Requirement |
|---|---|
| SDK-OBS-1 | Problems go to the `tallwright_cloud` logger and to `on_problem`, by type and record name, without content, salt or key; once per streak, not once per attempt. |
| SDK-OBS-2 | `status()` says how many records are queued and why sending stopped, if it did. |
| SDK-OBS-3 | `tallwright-cloud doctor` reports the Python version, the evidence store's guarantees, the door's reachability and, asked to, the key; it never takes the key as an argument. |
| SDK-OBS-4 | `gaps` shows numbers missing below the highest one of a session, and says it shows nothing about what was never captured. |

### The interface — `SDK-API`

| ID | Requirement |
|---|---|
| SDK-API-1 | Typed throughout (`py.typed`, `mypy --strict` clean). |
| SDK-API-2 | Depends on `tallwright-core`, and through it on `pydantic` 2 and `rfc8785`, and otherwise on the standard library; a bucket is reached through the integrator's own S3 client. |
| SDK-API-3 | `acapture` and `asubmit` keep an event loop free. |
| SDK-API-4 | The exhibit of a record is filed only beside the record this evidence sent, only if it says what the line said and, where a receipt was kept, sits where the receipt said. |

---

## 2. Test catalogue

What is tested, and against what standard. "Fake door" is a socket that answers what each test
tells it to; "real door" is Tallwright's recording door writing a real archive.

### 2.1 Security (OWASP ASVS 5.0 level 2, OWASP API Security Top 10 2023)

| Area | Standard | What is shown | Requirements |
|---|---|---|---|
| Cryptography | ASVS V11 | fresh 32-byte salt per record; address recomputed by the verifier; the commitment vectors | COM-2, COM-3 |
| Secrets in errors and logs | ASVS V16, API8 | a canary content and salt never appear in any repr, log record, exception or traceback frame, in either sending path | COM-4, OBS-1 |
| Transport | ASVS V12, API8 | plain http refused off loopback; certificate failure sends nothing; redirect not followed and the key not carried; no proxy for loopback | SND-1 |
| Unsafe consumption | API10 | receipts read strictly; answers bounded; a 200 without a receipt per line is not a confirmation; property-based: any receipt is this record's or unreadable, any 200 confirms a line only by its own receipt (`test_sdk_properties.py`) | SND-4, SND-8, SND-9 |
| Resource consumption | API4 | batches bounded in lines and bytes; backoff capped; one thread for many Environments | SND-5, SND-7, TEN-2 |
| Authorization boundaries | API1, API5 | evidence of one key never resent with another; each customer's evidence apart; the account key not in the recorder | EVD-9, TEN-1, ACC-4 |
| Data at rest | ASVS V14 | owner-only permissions; create-only stores | EVD-2, EVD-7 |

### 2.2 Evidence (Tallwright's own)

| Test | Requirements |
|---|---|
| Write-ahead order, and a crash after each step: nothing sent without a durable disclosure | EVD-1, EVD-4 |
| A record_id kept already is refused, never overwritten, in a directory and in a bucket | EVD-2, EVD-6 |
| A tampered disclosure or line is not sent | EVD-3 |
| A lost answer, resent: one record in the log, not two | SND-2, EVD-4 |
| An exhibit of a submitted record checks with the public verifier and the kept disclosure, and fails for one changed byte | API-4, EVD-8 |
| Holes in a session's sequence are shown, and only below its highest number | OBS-4 |
| A log rolled back past receipted records on the real door: the next receipt names the lost records, and they are recorded anew from the evidence | EVD-10, OBS-1 |

### 2.3 Failure

| Test | Requirements |
|---|---|
| Door down, then up: everything submitted is confirmed, in order, nothing twice | SND-5, SND-6 |
| 401 and 403 stop the client, keep the records pending, tell once | SND-7, OBS-1, OBS-2 |
| 503 storms back off and recover; another Environment's records still go | SND-7, TEN-2 |
| A batch answered with a 409 or a line refusal is split, and only the one line is refused | SND-3, SND-9 |
| A store that cannot be written refuses before sending | EVD-1 |
| A bucket that ignores conditional writes is reported by `check()` | EVD-6 |
| The bucket store through the real boto3 client against moto's S3: `PreconditionFailed`, `NoSuchKey`, `NoSuchBucket` read as they are (`test_s3_with_boto3.py`) | EVD-6 |

### 2.4 Load (measured, not asserted against a number that depends on the machine)

| Test | Requirements |
|---|---|
| `submit` returns before the door answers: a slow door does not slow it | SND-5 |
| Many submits from many threads: distinct names, no hole, all confirmed | LINE-4, SND-5 |
| Many Environments in one process: one thread | TEN-2 |
| A soak: many Environments, many threads, the real door, a share of answers lost after the door wrote; every record checked in the logs: once, in its own customer's log, its disclosure opening it, nothing left pending. Measured 2026-10-26: 20 Environments, 8 threads, 5,000 records, 5% answers lost: all held once; Windows/NTFS 219/s, submit p50 12 ms; Linux ext4 193/s, p50 21 ms | SND-2, SND-5, TEN-1, TEN-2, EVD-4 |

### 2.5 Interface and compatibility

| Test | Requirements |
|---|---|
| `mypy --strict` over the package; the public names exported | API-1 |
| Installed from its wheel, offline, into a fresh environment with nothing but `tallwright-core` and what it requires, and recording against a real door | API-2 |
| `acapture` and `asubmit` from a running event loop | API-3 |
| Linux, Windows and macOS; Python 3.11 to 3.13 (the CI matrix) | API-1 |

### 2.6 Outside this package, and not yet run

- Load against Tallwright's staging door with many Environments at once, and a 24-hour soak.
- The door's line parser is property-tested (any batch is recorded whole or refused by name leaving the log as it was; any body over HTTP gets a status the door was written to give, never a 500). This package's receipt reader and its reading of a 200 are property-tested too; the first run found a 200 with an empty receipt list that raised inside the sender, fixed.
- An external review of the commitment and the evidence path, if the owner decides on one.
- OpenSSF Scorecard and SLSA build provenance.
