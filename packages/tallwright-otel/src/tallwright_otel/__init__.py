# SPDX-License-Identifier: Apache-2.0
"""tallwright_otel — Cloud Proof from OpenTelemetry: a span processor for the generative-AI spans you have.

    from tallwright_otel import install

    install(TracerProvider(sampler=ALWAYS_ON), client)

- :func:`install` adds a :class:`TallwrightSpanProcessor` to a provider, and refuses a sampler that can
  drop a span (``processor.py``). Best effort only: a span reaches a processor after the tool ran.
"""

from __future__ import annotations

from .processor import SamplerDropsSpans, TallwrightSpanProcessor, install

__version__ = "0.1.0"

__all__ = ["install", "TallwrightSpanProcessor", "SamplerDropsSpans"]
