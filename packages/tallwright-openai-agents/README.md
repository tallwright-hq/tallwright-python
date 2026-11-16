# tallwright-openai-agents

Cloud Proof for an OpenAI Agents SDK run, as the SDK's own run hooks. The agent's context and the actions
it triggers become records that somebody else can check offline, while the content stays on your
machine.

It is a thin adapter on the Python SDK, [`tallwright-cloud`](https://docs.tallwright.com/python): it
decides when to hand the client an event and what content to hand it, and nothing else. The commitment,
the evidence, sending, sending again and the receipt are the SDK's
([the adapter contract](https://docs.tallwright.com/adapters)).

## Use it

```python
import os

from agents import Agent, Runner
from tallwright_cloud import Tallwright
from tallwright_openai_agents import TallwrightHooks

client = Tallwright(os.environ["TALLWRIGHT_INGEST"], os.environ["TALLWRIGHT_KEY"], "./tallwright-evidence")
agent = Agent(name="Refunds", instructions="Refund what policy allows.", tools=[refund])

result = await Runner.run(agent, "Refund ticket 8812", hooks=TallwrightHooks(client))
client.flush()  # at the end of a run: wait for what was sent in the background
```

The ingest address and the key are the ones the backoffice shows for an Environment, as in the
[quickstart](https://docs.tallwright.com/quickstart). The hooks never read a key and never choose where
evidence lives: you build the client, and you hand it over. A run takes one `hooks`; to add your own,
subclass `TallwrightHooks` and call `super()` in each hook you override.

## What becomes a record

- **Each model call**: the agent, its model, its instructions, the input items and the tools offered, as
  context the agent received.
- **Each tool call, before the tool runs**: the tool's name, its call id and its arguments, as an action,
  with the tool's name as its `action_type`.
- **What the tool returned**, as the agent received it, as context. A tool that raised returns what the
  SDK made of the error for the model, and that is what is recorded.
- **A handoff** to another agent, as an action with `action_type` `handoff`.

Never recorded: the agent's reasoning or intent. Reasoning items are left out of the input and named in
`omitted_input_items`; the model's own output is recorded as the next model call receives it. Named
credential keys (`api_key`, `token`, `authorization`, …) are replaced in arguments, messages and results,
with each path in `withheld_argument_keys` or `withheld_result_keys`. Pass `redact_keys=` to name more.

## Best effort or fail-closed

By default each event is handed to `client.asubmit`: it returns once the evidence is safe on your machine
and sends in the background. A capture that fails is logged by its type, never with content, the run goes
on, and the record stays in `pending()` until it is sent again.

```python
TallwrightHooks(client, fail_closed=True, actor_authority="role:payments-agent")
```

With `fail_closed=True`, each tool call and handoff is handed to `client.acapture` before it happens, and a
capture Tallwright did not confirm stops the tool: `Runner.run` raises it, wrapped in the SDK's
`UserError`. A regulated deployment sets it. `actor_authority` names the role or rule the agent's actions
run under, never a person.

## Many end customers

```python
from tallwright_cloud import Environments

environments = Environments(ingest_url, key_for, "./tallwright-evidence")
hooks = TallwrightHooks(client_for=lambda context: environments.client(context["customer"]))
await Runner.run(agent, prompt, hooks=hooks, context={"customer": "customer-42"})
```

`client_for` is called with the run's context, the object your code passed to `Runner.run`.
`hooks.pending()` and `hooks.flush()` reach every client the hooks used.

## What is outside the record

- **Anything that does not pass through the run's hooks**: a model or an API your code calls directly,
  and what a tool does inside itself.
- **Hosted tools that run on OpenAI's side** (web search, file search, code interpreter): the SDK does not
  run them locally, so no tool hook sees them; they appear only as items the next model call receives.
- **A credential inside free text**: keys are replaced where they are keys, not inside strings.
- **Whether what the agent was told was true.** A record commits to what was received, not to whether it
  was right.

The SDK's own tracing is unchanged: these hooks neither add a trace processor nor remove one.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the
license text and the NOTICE.
