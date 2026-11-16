# SPDX-License-Identifier: Apache-2.0
"""tallwright_mcp — Cloud Proof for MCP tool calls, by wrapping the client session you already hold.

    from tallwright_mcp import instrument

    instrument(session, client=client, server="payments")

- :func:`instrument` rebinds the session's ``call_tool`` so each call and its outcome is handed to a
  ``tallwright_cloud.Tallwright`` client (``session.py``);
- :mod:`tallwright_mcp.projection` is what a call becomes as content, the one decision an adapter makes;
  a self-hosted recorder commits to the same projection.

It does not import the MCP SDK.
"""

from __future__ import annotations

from .session import NotInstrumentable, instrument

__version__ = "0.1.0"

__all__ = ["instrument", "NotInstrumentable"]
