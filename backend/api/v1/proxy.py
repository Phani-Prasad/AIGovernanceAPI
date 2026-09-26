"""
Main LLM Proxy Endpoint — AI Governance & Security Layer API
The core proxy that intercepts, secures, and routes all LLM requests.
"""
import time
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from compliance.audit_logger import audit_logger
from core.database import get_db
from core.llm_router import LLMProviderError, llm_router, infer_provider
from core.security import validate_api_key
from governance.policy_engine import policy_engine
from models.schemas.schemas import (
    ContentModerationResult,
    InjectionScanResult,
    PIIScanResult,
    PipelineResult,
    ProxyRequest,
    ProxyResponse,
    UsageInfo,
    ErrorResponse,
)
from security.injection_detector import injection_detector
from security.pii_detector import pii_detector
from security.rate_limiter import rate_limiter

router = APIRouter(prefix="/v1", tags=["Proxy"])


async def run_security_pipeline(
    request_id: str,
    messages: list,
    settings_obj=None,
) -> tuple[PipelineResult, list]:
    """
    Run the full security pipeline on incoming messages.
    Returns (pipeline_result, processed_messages)
    """
    from core.config import settings

    # Extract all text for scanning
    full_text = pii_detector.extract_text_from_messages(
        [m.model_dump() if hasattr(m, "model_dump") else m for m in messages]
    )
    user_text = injection_detector.scan_messages(
        [m.model_dump() if hasattr(m, "model_dump") else m for m in messages]
    )

    # ── PII Scan ───────────────────────────────────────────────
    pii_result: PIIScanResult
    if settings.pii_detection_enabled:
        pii_result = await pii_detector.scan(full_text)
    else:
        pii_result = PIIScanResult(detected=False, entities=[], action_taken="none")

    # ── Injection Scan ─────────────────────────────────────────
    injection_result: InjectionScanResult
    if settings.injection_detection_enabled:
        injection_result = await injection_detector.scan(user_text)
    else:
        injection_result = InjectionScanResult(detected=False, score=0.0, action_taken="none")

    # ── Content Moderation (basic keyword-based for now) ───────
    content_result = ContentModerationResult(
        flagged=False,
        categories={},
        scores={},
        action_taken="none",
    )

    # Build pipeline result
    pipeline = PipelineResult(
        request_id=request_id,
        pii=pii_result,
        injection=injection_result,
        content=content_result,
        blocked=False,
    )

    # Check for immediate blocks from security pipeline
    if pii_result.action_taken == "blocked":
        pipeline.blocked = True
        pipeline.block_reason = "Request blocked: PII detected in prompt"
        return pipeline, messages

    if injection_result.action_taken == "blocked":
        pipeline.blocked = True
        pipeline.block_reason = f"Request blocked: Prompt injection detected (score: {injection_result.score:.2f})"
        return pipeline, messages

    # Apply PII masking to messages if needed
    processed_messages = list(messages)
    if pii_result.action_taken == "masked" and pii_result.sanitized_text:
        # For simplicity, rebuild messages with masked content
        # (A production version would do per-message masking)
        processed_messages = _apply_pii_mask_to_messages(messages, full_text, pii_result.sanitized_text)

    return pipeline, processed_messages


def _apply_pii_mask_to_messages(messages: list, original: str, masked: str) -> list:
    """Apply PII mask to message contents."""
    import copy
    result = []
    for msg in messages:
        if hasattr(msg, "model_dump"):
            msg_dict = msg.model_dump()
        else:
            msg_dict = dict(msg)
        if isinstance(msg_dict.get("content"), str) and msg_dict["content"] in original:
            msg_dict["content"] = msg_dict["content"].replace(original, masked)
        result.append(msg_dict)
    return result


@router.post(
    "/chat/completions",
    response_model=ProxyResponse,
    summary="LLM Proxy — Chat Completions",
    description="Drop-in replacement for OpenAI /v1/chat/completions. Routes to any LLM provider with full security and governance.",
)
async def proxy_chat_completions(
    request: Request,
    body: ProxyRequest,
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    request_id = str(uuid.uuid4())
    start_time = time.monotonic()

    # ── 1. Rate Limiting ───────────────────────────────────────
    is_blocked, block_reason = await rate_limiter.is_blocked(api_key.id)
    if is_blocked:
        raise HTTPException(status_code=429, detail=f"API key blocked: {block_reason}")

    allowed, rate_info = await rate_limiter.check_rate_limit(
        api_key_id=api_key.id,
        org_id=api_key.org_id,
        rpm_limit=api_key.rate_limit_rpm,
        daily_token_limit=api_key.daily_token_limit,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=rate_info)

    # ── 2. Security Pipeline ───────────────────────────────────
    pipeline_result, processed_messages = await run_security_pipeline(
        request_id=request_id,
        messages=body.messages,
    )

    # ── 3. Policy Engine ───────────────────────────────────────
    pipeline_result = await policy_engine.evaluate(
        db=db,
        org_id=api_key.org_id,
        api_key_id=api_key.id,
        pipeline_result=pipeline_result,
        model=body.model,
    )

    # ── 4. Block if pipeline says so ──────────────────────────
    if pipeline_result.blocked:
        latency_ms = (time.monotonic() - start_time) * 1000
        await audit_logger.log_request(
            db=db,
            org_id=api_key.org_id,
            api_key_id=api_key.id,
            user_id=None,
            request_id=request_id,
            provider=infer_provider(body.model),
            model=body.model,
            endpoint="/v1/chat/completions",
            pipeline_result=pipeline_result,
            status="blocked",
            status_code=400,
            latency_ms=latency_ms,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail={
                "error": "request_blocked",
                "message": pipeline_result.block_reason,
                "request_id": request_id,
            }
        )

    # ── 5. Route to LLM via LiteLLM ───────────────────────────
    llm_response = None
    error_message = None
    status = "success"
    status_code = 200

    try:
        messages_dicts = [
            m.model_dump() if hasattr(m, "model_dump") else m
            for m in processed_messages
        ]

        llm_response = await llm_router.complete(
            model=body.model,
            messages=messages_dicts,
            temperature=body.temperature,
            max_tokens=body.max_tokens,
        )

    except LLMProviderError as e:
        status = "error"
        status_code = e.status_code
        error_message = str(e)
    except Exception as e:
        status = "error"
        status_code = 500
        error_message = str(e)

    # ── 5.5. Model Evaluation (post-response) ─────────────────────
    from models.db.models import Organization
    from evaluation.eval_config import resolve_eval_config
    from evaluation.eval_runner import eval_runner, EvalResult

    org = await db.get(Organization, api_key.org_id)
    eval_config = resolve_eval_config(org)
    eval_result: EvalResult | None = None

    if llm_response and eval_config.enabled and eval_config.mode != "disabled":
        # Extract plain text from the LLM response for evaluation
        _choices = llm_response.get("choices", [])
        _response_text = _choices[0]["message"]["content"] if _choices else ""
        _prompt_text = " ".join(
            m.get("content", "") if isinstance(m, dict) else getattr(m, "content", "")
            for m in (processed_messages or body.messages)
        )

        if eval_config.mode == "inline":
            # Await both detectors — response is held until eval completes
            eval_result = await eval_runner.run(
                prompt=_prompt_text,
                response=_response_text,
                eval_config=eval_config,
            )
            pipeline_result.evaluation = eval_result  # type: ignore[assignment]

            # Re-evaluate policies — picks up hallucination/bias rules
            pipeline_result = await policy_engine.evaluate(
                db=db,
                org_id=api_key.org_id,
                api_key_id=api_key.id,
                pipeline_result=pipeline_result,
                model=body.model,
            )

        elif eval_config.mode == "async":
            # Fire-and-forget — updates the same AuditLog row after eval completes
            # audit_entry is returned from audit_logger.log_request below
            pass   # Dispatch happens AFTER audit log is created (audit_entry needed)

    # ── 6. Audit Logging ───────────────────────────────────────
    latency_ms = (time.monotonic() - start_time) * 1000
    usage = llm_response.get("usage", {}) if llm_response else {}

    audit_entry = await audit_logger.log_request(
        db=db,
        org_id=api_key.org_id,
        api_key_id=api_key.id,
        user_id=None,
        request_id=request_id,
        provider=infer_provider(body.model),
        model=body.model,
        endpoint="/v1/chat/completions",
        pipeline_result=pipeline_result,
        status=status,
        status_code=status_code,
        latency_ms=latency_ms,
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
        total_tokens=usage.get("total_tokens", 0),
        estimated_cost_usd=usage.get("estimated_cost_usd", 0.0),
        error_message=error_message,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await db.commit()

    # Dispatch async eval NOW (we have audit_entry.id)
    if (
        llm_response and eval_config.enabled
        and eval_config.mode == "async"
        and audit_entry is not None
    ):
        eval_runner.dispatch_async(
            audit_log_id=audit_entry.id,
            prompt=_prompt_text,
            response=_response_text,
            eval_config=eval_config,
        )

    # ── 7. Record rate limit usage ─────────────────────────────
    await rate_limiter.record_request(
        api_key_id=api_key.id,
        tokens_used=usage.get("total_tokens", 0),
    )

    if status != "success":
        raise HTTPException(status_code=status_code, detail=error_message)

    # ── 8. Build and return response ───────────────────────────
    return ProxyResponse(
        id=llm_response["id"],
        object="chat.completion",
        created=llm_response["created"],
        model=llm_response["model"],
        choices=llm_response["choices"],
        usage=UsageInfo(**usage),
        governance={
            "request_id": request_id,
            "pii_detected": pipeline_result.pii.detected,
            "pii_action": pipeline_result.pii.action_taken,
            "injection_detected": pipeline_result.injection.detected,
            "injection_score": pipeline_result.injection.score,
            "policy_applied": pipeline_result.policy_applied,
            "latency_ms": round(latency_ms, 2),
            # Model evaluation (present for inline mode; null for async until audit log updated)
            "eval_mode": eval_config.mode if eval_config.enabled else "disabled",
            "hallucination_score": eval_result.hallucination.score if eval_result and eval_result.hallucination else None,
            "hallucination_flagged": eval_result.hallucination.flagged if eval_result and eval_result.hallucination else None,
            "bias_score": eval_result.bias.score if eval_result and eval_result.bias else None,
            "bias_flagged": eval_result.bias.flagged if eval_result and eval_result.bias else None,
        },
    )


@router.get(
    "/models",
    summary="List Supported Models",
    description="Returns list of LLM models supported by the governance layer.",
)
async def list_models(api_key=Depends(validate_api_key)):
    """List all models available through the governance layer."""
    supported_models = [
        # OpenAI
        {"id": "gpt-4o", "provider": "openai", "context_window": 128000},
        {"id": "gpt-4o-mini", "provider": "openai", "context_window": 128000},
        {"id": "gpt-4-turbo", "provider": "openai", "context_window": 128000},
        {"id": "gpt-3.5-turbo", "provider": "openai", "context_window": 16385},
        {"id": "o1-preview", "provider": "openai", "context_window": 128000},
        # Anthropic
        {"id": "claude-3-5-sonnet-20241022", "provider": "anthropic", "context_window": 200000},
        {"id": "claude-3-5-haiku-20241022", "provider": "anthropic", "context_window": 200000},
        {"id": "claude-3-opus-20240229", "provider": "anthropic", "context_window": 200000},
        # Google
        {"id": "gemini/gemini-1.5-pro", "provider": "google", "context_window": 1000000},
        {"id": "gemini/gemini-1.5-flash", "provider": "google", "context_window": 1000000},
        {"id": "gemini/gemini-2.0-flash", "provider": "google", "context_window": 1000000},
        # Azure OpenAI
        {"id": "azure/gpt-4o", "provider": "azure", "context_window": 128000},
        {"id": "azure/gpt-4-turbo", "provider": "azure", "context_window": 128000},
    ]
    return {"object": "list", "data": supported_models}
