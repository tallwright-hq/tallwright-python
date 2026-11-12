# Changelog

## tallwright-cloud 1.0.0rc1, tallwright-core 0.1.0

The first release, as a release candidate: `pip install tallwright-cloud==1.0.0rc1`. 1.0.0 follows once
it has been used for real.

- `tallwright-cloud`: the recorder for Cloud Proof. `capture` and `submit` (and `acapture`,
  `asubmit`), evidence kept in a directory or an S3-compatible bucket, a background sender that sends
  again after a crash, `Environments` for many end customers, `Account` for making and keeping
  Environments, `Exhibits` for taking the exhibit of a record, and the `tallwright-cloud` command
  line (`doctor`, `pending`, `resend`, `gaps`). What 1.0 promises is in
  `packages/tallwright-cloud/SPEC.md`.
- `tallwright-core` 0.1.0: the version the public verifier 0.1.0 carries, byte for byte.
- Python 3.11, 3.12 and 3.13 on Linux, Windows and macOS.
