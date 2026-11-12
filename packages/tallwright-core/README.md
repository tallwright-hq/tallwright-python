# tallwright-core

The dependency-light foundation every other Tallwright package builds on. No
networked or external-service code lives here.

- **`hashing.py`** — SHA-256 self-describing multihash + multibase content-addressing
- **`merkle.py`** — RFC 6962 Merkle tree: root, inclusion + consistency proofs, and
  independent (RFC 9162) verifiers
- **`schema.py`** — the 14-field record envelope,
  RFC 8785 (JCS) canonicalization, record hash, and hash-chain (`link` / `verify_chain`).
  Post-seal fields (`anchor_receipt`, `certification_pointer`) are excluded from the hash.

Status: **implemented + tested** (the first approved production code). Anchoring, signing,
storage, and capture live in later packages.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the license
text and the NOTICE. The exhibit
format's specification and its test vectors are under the same license; the rest of Tallwright is
proprietary.
