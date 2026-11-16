# tallwright-langgraph

Cloud Proof for a LangChain/LangGraph v1 agent, as one middleware. The agent's context and the actions
it triggers become records that somebody else can check offline, while the content stays on your
machine.

It is a thin adapter on the Python SDK, [`tallwright-cloud`](https://docs.tallwright.com/python): it
decides when to hand the client an event and what content to hand it, and nothing else. The commitment,
the evidence, sending, sending again and the receipt are the SDK's
([the adapter contract](https://docs.tallwright.com/adapters)).

## Use it

```python
import os

from langchain.agents import create_agent
from tallwright_cloud import Tallwright
from tallwright_langgraph import TallwrightMiddleware

client = Tallwright(os.environ["TALLWRIGHT_INGEST"], os.environ["TALLWRIGHT_KEY"], "./tallwright-evidence")
agent = create_agent(model, tools, middleware=[TallwrightMiddleware(client)])  # last in the list

agent.invoke({"messages": [{"role": "user", "content": "Refund ticket 8812"}]})
client.flush()  # at the end of a run: wait for what was sent in the background
```

The ingest address and the key are the ones the backoffice shows for an Environment, as in the
[quickstart](https://docs.tallwright.com/quickstart). The middleware never reads a key and never chooses
where evidence lives: you build the client, and you hand it over.

## What becomes a record

- **Each model call**: what the model received (system message, messages, the tools offered, the model's
  name), as context the agent received.
- **Each tool call, before the tool runs**: the tool's name and its arguments, as an action, with the
  tool's name as its `action_type`.
- **What the tool returned**, or the type of the exception it raised, as context.

Never recorded: the agent's reasoning or intent. LangChain has no hook for intent, and a provider's
reasoning blocks are left out of what is committed. Messages are projected onto named fields; what was
left out is named in `omitted_message_fields`, and named credential keys (`api_key`, `token`,
`authorization`, …) are replaced in arguments, messages and results, with each path in
`withheld_argument_keys` or `withheld_result_keys`. Pass `redact_keys=` to name more.

## Best effort or fail-closed

By default each event is handed to `client.submit`: it returns once the evidence is safe on your machine
and sends in the background, so the agent never waits on the network. A capture that fails is logged by
its type, never with content, the agent keeps serving, and the record stays in `pending()` until it is
sent again.

```python
TallwrightMiddleware(client, fail_closed=True, actor_authority="role:payments-agent")
```

With `fail_closed=True`, each tool call is handed to `client.capture` before the tool runs, and a capture
Tallwright did not confirm raises before the tool runs. A regulated deployment sets it.
`actor_authority` names the role or rule the agent's actions run under, never a person.

## Many end customers

One agent process that serves many end customers records each run into that customer's Environment:

```python
from tallwright_cloud import Environments

environments = Environments(ingest_url, key_for, "./tallwright-evidence")
middleware = TallwrightMiddleware(client_for=lambda runtime: environments.client(runtime.context["customer"]))
agent.invoke(inputs, context={"customer": "customer-42"})
```

`client_for` is called with the run's LangGraph `runtime`; its `context` is what your code passed to
`invoke`. `middleware.pending()` and `middleware.flush()` reach every client the middleware used.

## What is outside the record

- **A middleware listed after this one.** LangChain composes middleware outermost first, and this one
  records the tool call before calling the handler. A middleware listed after it runs inside it and may
  rewrite the call afterwards (context editing, PII, summarization, tool selection, human-in-the-loop),
  and the record then describes the call as it was before. Install it last.
- **Anything that does not pass through the agent's model and tool hooks**: a model or an API your code
  calls directly, and what a tool does inside itself.
- **A credential inside free text.** Keys are replaced where they are keys; a secret written into a
  string, such as a tool result the framework turned into text for the model, is not recognised.
- **Whether what the agent was told was true.** A record commits to what was received, not to whether it
  was right.

## License

Copyright 2026 David Jöbstl. Licensed under the Apache License, Version 2.0: the package carries the
license text and the NOTICE.
