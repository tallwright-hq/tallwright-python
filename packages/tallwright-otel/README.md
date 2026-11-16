# tallwright-otel

Cloud Proof from OpenTelemetry: a span processor that hands the Python SDK the generative-AI spans your
tracing already has. Any instrumentation that follows the
[OpenTelemetry semantic conventions for generative AI](https://github.com/open-telemetry/semantic-conventions-genai)
feeds it, whatever framework it instruments.

It is a thin adapter on [`tallwright-cloud`](https://docs.tallwright.com/python): it decides when to hand
the client an event and what content to hand it, and nothing else
([the adapter contract](https://docs.tallwright.com/adapters)).

## Use it

```python
import os

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from tallwright_cloud import Tallwright
from tallwright_otel import install

client = Tallwright(os.environ["TALLWRIGHT_INGEST"], os.environ["TALLWRIGHT_KEY"], "./tallwright-evidence")
provider = TracerProvider(sampler=ALWAYS_ON)
install(provider, client)
trace.set_tracer_provider(provider)
```

Then turn on your instrumentation's content capture (the conventions make arguments, results and
messages opt-in), and at the end of a run call `client.flush()`.

## What becomes a record

- **An `execute_tool` span**: the tool's name, its call id and its arguments, as an action with the tool's
  name as its `action_type`; then what it returned, or the type of its error, as context.
- **A `chat`, `text_completion` or `generate_content` span**: the model, its system instructions and the
  input messages, as context the agent received.

Each record carries the moment the span gives (`timestamp`: its start, or its end for an outcome), and
its content names the trace and the span, so a record and the trace it came from can be found from each
other. Reasoning parts are left out and named in `omitted_parts`; named credential keys are replaced,
with each path in `withheld_argument_keys` or `withheld_result_keys`. What a span did not carry is named
in `absent`, never guessed.

## What it cannot do, by construction

- **It never stops an action.** A span reaches a processor when it ends, after the tool ran. This adapter
  records actions afterwards, is best effort only, and offers no fail-closed mode. A deployment that must
  not act unrecorded uses a framework adapter: [`tallwright-langgraph`](https://docs.tallwright.com/adapters),
  `tallwright-openai-agents` or `tallwright-mcp`.
- **It sees only sampled spans.** A span that was not sampled reaches no processor, so `install` refuses
  a provider whose sampler can drop one; the SDK's default, which follows an unsampled parent from
  another service, is refused too. Sample in your collector instead.
- **It records what the spans carry, as the instrumentation set it.** An instrumentation that leaves a
  call untraced, or content capture left off, leaves that out of the record. The conventions themselves
  are still in development.
- **A failure is logged by its type, never with content**, and tracing goes on.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the
license text and the NOTICE.
