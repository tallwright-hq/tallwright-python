# Security policy

## Reporting a vulnerability

Report a suspected vulnerability privately: by GitHub's
[private vulnerability reporting](https://github.com/tallwright-hq/tallwright-python/security/advisories/new)
on this repository, or by email to **hello@tallwright.com**. Please do not open a public issue for it.

Include the package and its version (`python -m pip show tallwright-cloud`), your Python's version,
and how to reproduce it. There is no security response time promised yet, and disclosure is
coordinated on a best-effort basis.

**Never send** the content you recorded, a `disclosure.json`, or a key: not a recording key, not an
export key, not an account key, and not an exhibit link. No report needs them, and each one is a
credential or the evidence itself.

## Scope

In scope: the code in this repository, `tallwright-cloud` and `tallwright-core`, and the releases
published from it.

Tallwright's hosted service is in scope too, but please describe what you found rather than
demonstrate it: do not scan, load-test or run destructive tests against it, and never against
somebody else's data. Write first.

## Supported versions

The latest release. Before 1.0.0, only the latest release candidate.
