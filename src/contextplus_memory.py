from __future__ import annotations

"""Utility memory adapter that combines throttling + compression.

If `autogen_contextplus` is available we register a compressor so that any
text that looks like raw HTML (or is > 2 000 characters) is replaced with a
concise summary produced by our existing `summarise_http_response` helper.
Otherwise we fall back to a pure python implementation that overrides the
`add` method of `ThrottledListMemory`.

The goal is to keep long, noisy scanner output and raw HTML out of the vector
store / memory prompt while still preserving the salient security-relevant
information.
"""

from typing import Any

from autogen_core.memory import ListMemory, MemoryContent, MemoryMimeType

# Local helper that trims/summarises HTML
from tools import summarise_http_response

# --- Optional: Autogen-ContextPlus integration -----------------------------
try:
    from autogen_contextplus import MemoryManager, Compressor

    class _HtmlCompressor(Compressor):  # type: ignore
        """ContextPlus compressor that summarises long HTML blocks."""

        def compress(self, text: str, metadata: dict[str, Any] | None = None) -> str:  # noqa: D401
            if "<html" in text.lower() or len(text) > 2000:
                return summarise_http_response(text)
            return text

    def build_memory(throttle: int = 3) -> MemoryManager:  # type: ignore
        """Return a ContextPlus MemoryManager with throttling + HTML compression."""
        mgr = MemoryManager()
        mgr.register_compressor(_HtmlCompressor())
        mgr.throttle = throttle  # type: ignore[attr-defined]
        return mgr

    # Alias for external code expecting ListMemory-like interface
    CompressedThrottledMemory = MemoryManager  # type: ignore

except ImportError:  # Graceful fallback -------------------------------------------------

    # No ContextPlus: fallback to simple ListMemory variant without unsafe relative imports.

    from autogen_core.memory import ListMemory  # re-import for fallback

    class CompressedThrottledMemory(ListMemory):
        """Fallback: throttle retrieval and compress HTML on write."""

        def __init__(self, throttle: int = 3, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._throttle = max(1, throttle)
            self._counter = 0

        async def add(self, content: MemoryContent, *args, **kwargs):  # type: ignore[override]
            # Compress only TEXT content
            if (
                content.mime_type == MemoryMimeType.TEXT
                and isinstance(content.content, str)
                and (
                    "<html" in content.content.lower() or len(content.content) > 2000
                )
            ):
                content = MemoryContent(
                    content=summarise_http_response(content.content),
                    mime_type=MemoryMimeType.TEXT,
                )
            return await super().add(content, *args, **kwargs)

        async def query(self, query_text: str, *args, **kwargs):  # type: ignore[override]
            self._counter += 1
            if self._counter % self._throttle != 0:
                return []
            return await super().query(query_text, *args, **kwargs) 