# SPDX-License-Identifier: Apache-2.0
"""tallwright_openai_agents — Cloud Proof for an OpenAI Agents SDK run, as the SDK's own run hooks.

    from tallwright_openai_agents import TallwrightHooks

    result = await Runner.run(agent, prompt, hooks=TallwrightHooks(client))

- :class:`TallwrightHooks` hands a ``tallwright_cloud.Tallwright`` client the run's context and actions
  (``hooks.py``);
- :mod:`tallwright_openai_agents.projection` is what those events become as content, the one decision an
  adapter makes.
"""

from __future__ import annotations

from .hooks import TallwrightHooks

__version__ = "0.1.0"

__all__ = ["TallwrightHooks"]
