# Changelog

## tallwright-cloud 1.0.0rc2, tallwright-core 0.1.1, and the four integrations 0.1.0

The first release of the framework integrations, listed under "Integrations" in the README: each is
installed by its name, for example `pip install tallwright-langgraph`, and the SDK alone stays
`pip install tallwright-cloud==1.0.0rc2`.

- `tallwright-langgraph`, `tallwright-mcp`, `tallwright-openai-agents` and `tallwright-otel` 0.1.0:
  LangChain and LangGraph v1, MCP tool calls, the OpenAI Agents SDK, and OpenTelemetry generative-AI
  spans, each handing the SDK the events it sees.
- `tallwright-core` 0.1.1: adds `tallwright_core.redact`, which the integrations use to withhold named
  credential keys. The version the public verifier 0.1.1 carries, byte for byte.
- `tallwright-cloud` 1.0.0rc2: the code of 1.0.0rc1 under the version this release is tagged with.

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
