"""secure/ai/providers/ — one module per local model backend (ollama.py,
openai_compatible.py), each exposing a build_provider(cfg) function.
See secure/ai/registry.py for how these are assembled, and
secure/ai/base.py for the shared provider shape.
"""

from __future__ import annotations
