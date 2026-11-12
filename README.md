# Tallwright Python SDK

[![PyPI](https://img.shields.io/pypi/v/tallwright-cloud.svg)](https://pypi.org/project/tallwright-cloud/)
[![Python versions](https://img.shields.io/pypi/pyversions/tallwright-cloud.svg)](https://pypi.org/project/tallwright-cloud/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Tallwright Cloud Proof records what your AI agent did as tamper-evident evidence that somebody
else can check offline, while the content of what it did stays on your own machine.**

Your code commits to each action where it happens. A salted address of the content goes to
Tallwright; the content and the salt that opens the address stay with you. Tallwright seals the
address into an append-only log, a witness countersigns the log's head, and for any record you can
ask for an **exhibit**: one file that anyone can check offline with the public verifier, against the
content you choose to disclose to them.

This repository holds the SDK, [`tallwright-cloud`](packages/tallwright-cloud), and the core it
builds on, [`tallwright-core`](packages/tallwright-core).

## What the SDK does

- **Records where the action happens.** `capture()` waits for Tallwright's receipt and raises when
  it does not come. `submit()` returns once the evidence is safe and sends in the background, for
  an agent that must not wait on the network. Both have async forms.
- **Keeps the evidence before it sends.** The content and its salt are written to your evidence
  store first: a local directory, or a bucket of anything that speaks S3. Nothing in it is ever
  overwritten.
- **Loses no record quietly.** A lost answer is sent again byte for byte, and a record Tallwright
  already holds is never written twice. A record that is never confirmed stays pending, listed by
  `client.pending()`, until it is sent again.
- **One Environment per end customer**, each with its own key and its own evidence, all through one
  sending thread.
- **Takes the exhibit** of a record, with an export key or the one-time link the backoffice gives.
- **Says what is wrong.** `tallwright-cloud doctor` reports what stands between a machine and
  evidence somebody can check.

## What an exhibit shows, and what it does not

An exhibit shows that a record has not changed since it reached Tallwright, at its position in the
log, under a log head the witness countersigned. You, and anyone you give the exhibit and your
disclosure to, can check that offline with the public verifier; a disclosure with one changed byte
of the content fails the check.

It does not show that what the record says is true, or that your system recorded every action it
took: integrity of what was captured, not completeness of what happened. On Cloud, Tallwright hosts
the log and runs the witness, and nothing here claims they are independent of each other.

## Installation

```bash
pip install tallwright-cloud==1.0.0rc1
```

Python 3.11, 3.12 or 3.13. This is a release candidate: pin the version as shown. The SDK requires
`tallwright-core`, which brings `pydantic` 2 and `rfc8785`; its HTTP client is the standard
library's.

## Quickstart

You need an **Environment** in the Tallwright backoffice at <https://app.tallwright.com>, and its
two values: the **ingest address**, and the **key**, which is shown once. Keep the key in your
secret store, out of your code and out of your logs.

```bash
export TALLWRIGHT_INGEST='<the ingest address the backoffice shows>'
export TALLWRIGHT_KEY='<the key of the Environment>'
```

```python
import os
from tallwright_cloud import Tallwright

client = Tallwright(os.environ["TALLWRIGHT_INGEST"], os.environ["TALLWRIGHT_KEY"], "./tallwright-evidence")
captured = client.capture("Refund of 120 EUR approved for ticket 8812", action_type="refund.approved")
print(captured.record_id, captured.receipt.status, captured.receipt.leaf_index)
```

`capture` commits to the content, keeps the evidence, sends the line and waits for the receipt.
`./tallwright-evidence/<record_id>/` now holds `disclosure.json` (your content and its salt),
`line.json` (what was sent) and `receipt.json` (what came back). That folder is the only copy of
your content and of the salt that opens the record: keep it the way you keep the records it
describes.

The receipt is a confirmation, not yet a proof. Once a witness has covered the record at the next
anchor run, take its exhibit and check it yourself, offline: steps 2 and 3 of the
[quickstart](https://docs.tallwright.com/quickstart).

## What stays with you, and what is sent

| Sent to Tallwright | Kept by you, in your evidence store |
|---|---|
| `payload_hash`: the address of the salt followed by the content | the content |
| `record_id` | the 32-byte salt |
| `action_type`, `actor_authority` and `timestamp`, when you give them | `disclosure.json`, which opens the address for whoever you give it to |

- What is sent travels in the clear and is sealed into every exhibit. Name events, kinds and rules
  in it, never people.
- The SDK sends only to the addresses you give it, over HTTPS (plain HTTP only to an address on the
  same machine), and follows no redirect. Each request names the SDK and its version in its
  User-Agent.
- The content, the salt and the key are kept out of the SDK's messages, logs and reprs.
- Environments made from code with `Account` send the name, `customer_ref` and label you give them.

## Documentation

- [Overview](https://docs.tallwright.com): how a record becomes a proof
- [Quickstart](https://docs.tallwright.com/quickstart): from an Environment to an exhibit you have
  checked yourself
- [Python SDK guide](https://docs.tallwright.com/python): sending in the background, evidence
  stores, many end customers, pending records
- [API reference](https://docs.tallwright.com/python/api) and the
  [errors](https://docs.tallwright.com/errors) it raises
- [Guarantees](https://docs.tallwright.com/python/guarantees): what the SDK promises, and the test
  that holds each promise
- [Cloud Proof over HTTP](https://docs.tallwright.com/http): the same contract for a language
  without an SDK
- [Exhibit format](https://docs.tallwright.com/exhibits): what an exhibit proves, and how a verifier
  checks it
- [Public verifier](https://verify.tallwright.com/): `evidence-verify`, to check an exhibit offline
- [Getting help](https://docs.tallwright.com/support): hello@tallwright.com

## Security

Report a suspected vulnerability privately, as [SECURITY.md](SECURITY.md) says, and not in a public
issue. Never send content you recorded, a `disclosure.json` or a key.

## Contributing

Issues are welcome. Pull requests are not accepted yet: each release is made in Tallwright's own
repository and arrives here as one commit. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Releases are published to PyPI from this repository by Trusted Publishing. `release/` lists the
SHA-256 of each release's wheels, the bytes PyPI serves. What changed is in
[CHANGELOG.md](CHANGELOG.md).

## License

`tallwright-cloud` and `tallwright-core` are licensed under the Apache License, Version 2.0: see
[LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 David Jöbstl.
