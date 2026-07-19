"""Provider abstraction layer for LLM inference backends.

The :class:`~forge.providers.llama_cpp.LlamaCppProvider` MVP backend is
re-exported for convenience. Its module-level import is safe in environments
without ``llama-cpp-python`` installed because the native library is loaded
lazily inside ``LlamaCppProvider.__init__`` rather than at import time.
Additional backends (Ollama, vLLM, OpenAI-compatible) are intentionally not
re-exported here; they are resolved lazily by :class:`ProviderRegistry` on
first :meth:`get` call so importing this package never triggers backend
library loads beyond the MVP backend.
"""

from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
    ProviderUnavailableError,
)
from forge.providers.llama_cpp import LlamaCppProvider
from forge.providers.registry import ProviderFactory, ProviderRegistry

__all__ = [
    "CompletionRequest",
    "CompletionResponse",
    "LLMProvider",
    "LlamaCppProvider",
    "ProviderFactory",
    "ProviderRegistry",
    "ProviderUnavailableError",
]
