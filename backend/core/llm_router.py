"""
LLM Router — AI Governance & Security Layer API
LiteLLM-based universal provider routing with cost tracking.
"""
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

import litellm
from litellm import acompletion, completion_cost
from litellm.exceptions import (
    AuthenticationError,
    BadRequestError,
    RateLimitError,
    ServiceUnavailableError,
)

from core.config import settings

# ── LiteLLM Configuration ──────────────────────────────────────
litellm.set_verbose = settings.debug

# Provider key injection — LiteLLM reads these from env too,
# but we set them explicitly from our config for multi-tenant support
_DEFAULT_PROVIDER_KEYS = {
    "OPENAI_API_KEY": settings.openai_api_key,
    "ANTHROPIC_API_KEY": settings.anthropic_api_key,
    "GEMINI_API_KEY": settings.gemini_api_key,
    "GROQ_API_KEY": settings.groq_api_key,
    "AZURE_API_KEY": settings.azure_api_key,
    "COHERE_API_KEY": settings.cohere_api_key,
}


def _get_litellm_kwargs(model: str, provider_api_key: Optional[str] = None) -> Dict[str, Any]:
    """Build extra kwargs for LiteLLM based on model and optional override key."""
    kwargs: Dict[str, Any] = {}

    # Azure requires special params
    if model.startswith("azure/"):
        kwargs["api_base"] = settings.azure_api_base
        kwargs["api_version"] = settings.azure_api_version
        if provider_api_key:
            kwargs["api_key"] = provider_api_key
    elif provider_api_key:
        kwargs["api_key"] = provider_api_key

    return kwargs


def infer_provider(model: str) -> str:
    """Infer provider name from model string."""
    model_lower = model.lower()
    if model_lower.startswith("groq/") or "llama" in model_lower:
        return "groq"
    if model_lower.startswith("gpt") or model_lower.startswith("o1") or model_lower.startswith("o3"):
        return "openai"
    if model_lower.startswith("claude"):
        return "anthropic"
    if model_lower.startswith("gemini"):
        return "google"
    if model_lower.startswith("azure/"):
        return "azure"
    if model_lower.startswith("command"):
        return "cohere"
    if model_lower.startswith("meta.llama") or model_lower.startswith("amazon"):
        return "bedrock"
    return "unknown"


class LLMRouter:
    """
    Thin wrapper around LiteLLM providing:
    - Unified completion interface
    - Cost tracking
    - Error normalization
    - Streaming support
    """

    async def complete(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        provider_api_key: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Route a chat completion request through LiteLLM.
        Returns a normalized response dict.
        """
        start_time = time.monotonic()
        extra = _get_litellm_kwargs(model, provider_api_key)
        extra.update(kwargs)

        try:
            response = await acompletion(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False,
                **extra,
            )

            latency_ms = (time.monotonic() - start_time) * 1000

            # Extract usage
            usage = getattr(response, "usage", None)
            prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
            completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
            total_tokens = getattr(usage, "total_tokens", 0) if usage else 0

            # Cost calculation
            try:
                cost = completion_cost(completion_response=response)
            except Exception:
                cost = 0.0

            return {
                "id": response.id,
                "object": "chat.completion",
                "created": response.created,
                "model": response.model,
                "choices": [
                    {
                        "index": c.index,
                        "message": {
                            "role": c.message.role,
                            "content": c.message.content,
                        },
                        "finish_reason": c.finish_reason,
                    }
                    for c in response.choices
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                    "estimated_cost_usd": round(cost, 8),
                },
                "_meta": {
                    "provider": infer_provider(model),
                    "latency_ms": round(latency_ms, 2),
                },
            }

        except AuthenticationError as e:
            raise LLMProviderError(f"Authentication failed for model '{model}': {e}", status_code=401)
        except RateLimitError as e:
            raise LLMProviderError(f"Rate limit exceeded for model '{model}': {e}", status_code=429)
        except BadRequestError as e:
            raise LLMProviderError(f"Bad request to model '{model}': {e}", status_code=400)
        except ServiceUnavailableError as e:
            raise LLMProviderError(f"Provider unavailable for model '{model}': {e}", status_code=503)
        except Exception as e:
            raise LLMProviderError(f"Unexpected error routing to '{model}': {e}", status_code=500)

    async def stream_complete(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        provider_api_key: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """Stream a chat completion via Server-Sent Events."""
        extra = _get_litellm_kwargs(model, provider_api_key)
        extra.update(kwargs)

        response = await acompletion(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **extra,
        )

        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                content = chunk.choices[0].delta.content
                yield f"data: {content}\n\n"

        yield "data: [DONE]\n\n"

    def list_supported_providers(self) -> List[str]:
        return ["openai", "anthropic", "google", "azure", "cohere", "bedrock", "mistral", "groq"]


class LLMProviderError(Exception):
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


# ── Singleton Router ───────────────────────────────────────────
llm_router = LLMRouter()
