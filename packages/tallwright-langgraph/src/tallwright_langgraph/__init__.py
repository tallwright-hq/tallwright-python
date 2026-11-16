# SPDX-License-Identifier: Apache-2.0
"""tallwright_langgraph — Cloud Proof for a LangChain/LangGraph v1 agent, as one middleware.

    from tallwright_langgraph import TallwrightMiddleware

    agent = create_agent(model, tools, middleware=[TallwrightMiddleware(client)])   # last in the list

- :class:`TallwrightMiddleware` hands a ``tallwright_cloud.Tallwright`` client the agent's context and
  actions (``middleware.py``);
- :mod:`tallwright_langgraph.projection` is what those events become as content, the one decision an
  adapter makes; a self-hosted recorder commits to the same projection.

The middleware is loaded when it is first named, so a reader of the projection alone does not load the
Cloud client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - names for the type checker only
    from .middleware import TallwrightMiddleware

__version__ = "0.1.0"

__all__ = ["TallwrightMiddleware"]


def __getattr__(name: str) -> Any:
    if name == "TallwrightMiddleware":
        from .middleware import TallwrightMiddleware

        return TallwrightMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
