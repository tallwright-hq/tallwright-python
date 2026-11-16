# tallwright-mcp

Cloud Proof for MCP tool calls, by wrapping the client session you already hold. Each call and what it
returned become records that somebody else can check offline, while the content stays on your machine.

It is a thin adapter on the Python SDK, [`tallwright-cloud`](https://docs.tallwright.com/python): it
decides when to hand the client a call and what content to hand it, and nothing else
([the adapter contract](https://docs.tallwright.com/adapters)). It does not import the MCP SDK: it
rebinds the `call_tool` coroutine your session already has, so it works across SDK versions and adds
nothing to your dependencies.

## Use it

```python
import os

from mcp import ClientSession
from tallwright_cloud import Tallwright
from tallwright_mcp import instrument

client = Tallwright(os.environ["TALLWRIGHT_INGEST"], os.environ["TALLWRIGHT_KEY"], "./tallwright-evidence")

async with ClientSession(read, write) as session:
    await session.initialize()
    instrument(session, client=client, server="payments")
    await session.call_tool("refund", {"ticket": "8812"})

client.flush()  # at the end of a run: wait for what was sent in the background
```

The ingest address and the key are the ones the backoffice shows for an Environment, as in the
[quickstart](https://docs.tallwright.com/quickstart). `instrument` rebinds `call_tool` on the session
itself, so every holder of the session records, not only the reference you passed; instrumenting twice
changes nothing, and an object with no `call_tool` is refused rather than handed back unrecorded.

## What becomes a record

- **Each tool call, before it is made**: the server's name, the tool's name and the arguments, as an
  action with `action_type` `mcp:<tool>`.
- **What the tool returned**, reduced by the result object's own dump, or the type of the exception the
  call raised, as context.

Named credential keys (`api_key`, `token`, `authorization`, …) are replaced in arguments and results,
with each path in `withheld_argument_keys` or `withheld_result_keys`. Pass `redact_keys=` to name more.

## Best effort or fail-closed

By default each event is handed to `client.submit`: it returns once the evidence is safe on your machine
and sends in the background. A capture that fails is logged by its type, never with content, the call
goes on, and the record stays in `client.pending()` until it is sent again.

```python
instrument(session, client=client, server="payments", fail_closed=True, actor_authority="role:payments-agent")
```

With `fail_closed=True`, each call is handed to `client.capture` before it is made, and a capture
Tallwright did not confirm raises before the tool is called. `actor_authority` names the role or rule
the calls run under, never a person. A vendor with many end customers instruments each customer's
session with that customer's client (`Environments.client`).

## What is outside the record

- **The model's decision.** The wrapper sees the protocol boundary: the call as it is made. What the
  agent was told, and why it chose the tool, are not on this session.
- **What the server does behind the tool**, and any call that does not go through this session.
- **A credential inside free text**: keys are replaced where they are keys, not inside strings.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the
license text and the NOTICE.
