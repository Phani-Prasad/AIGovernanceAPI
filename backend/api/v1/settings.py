"""
Settings API — AI Governance & Security Layer API
Org-level configuration management, including model evaluation settings.
"""
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import validate_api_key
from evaluation.eval_config import resolve_eval_config

router = APIRouter(prefix="/v1/orgs", tags=["Settings"])


# ── Request schemas ────────────────────────────────────────────

class HallucinationConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    method: Optional[Literal["llm_judge", "self_consistency", "grounding"]] = None
    judge_model: Optional[str] = None
    threshold: Optional[float] = None
    on_flag: Optional[Literal["block", "warn", "log_only"]] = None


class BiasConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    method: Optional[Literal["toxicity", "llm_judge", "both"]] = None
    threshold: Optional[float] = None
    on_flag: Optional[Literal["block", "warn", "log_only"]] = None
    categories: Optional[list[str]] = None


class EvalConfigUpdate(BaseModel):
    """Partial update schema — only set fields are applied."""
    enabled: Optional[bool] = None
    mode: Optional[Literal["inline", "async", "disabled"]] = None
    hallucination: Optional[HallucinationConfigUpdate] = None
    bias: Optional[BiasConfigUpdate] = None


# ── Helpers ────────────────────────────────────────────────────

def _require_admin(api_key):
    """Ensure caller has admin role (checked via API key permissions)."""
    if "admin" not in (api_key.permissions or []):
        raise HTTPException(
            status_code=403,
            detail="Admin permission required to manage org settings",
        )


async def _get_org(db: AsyncSession, org_id: str):
    from models.db.models import Organization
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# ── Endpoints ──────────────────────────────────────────────────

@router.get(
    "/me/settings/evaluation",
    summary="Get Org Evaluation Config",
    description=(
        "Returns the effective model evaluation configuration for the caller's org. "
        "Shows merged global defaults + any org-level overrides."
    ),
)
async def get_eval_config(
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    """Return effective eval config (defaults merged with org overrides)."""
    _require_admin(api_key)
    org = await _get_org(db, api_key.org_id)
    config = resolve_eval_config(org)

    return {
        "success": True,
        "org_id": api_key.org_id,
        "evaluation": {
            "enabled": config.enabled,
            "mode": config.mode,
            "hallucination": {
                "enabled": config.hallucination.enabled,
                "method": config.hallucination.method,
                "judge_model": config.hallucination.judge_model,
                "threshold": config.hallucination.threshold,
                "on_flag": config.hallucination.on_flag,
            },
            "bias": {
                "enabled": config.bias.enabled,
                "method": config.bias.method,
                "threshold": config.bias.threshold,
                "on_flag": config.bias.on_flag,
                "categories": config.bias.categories,
            },
        },
        "overrides": org.settings.get("model_evaluation", {}),
        "note": "Effective config = global defaults merged with org-level overrides shown above.",
    }


@router.patch(
    "/me/settings/evaluation",
    summary="Update Org Evaluation Config",
    description=(
        "Partially update model evaluation settings for the caller's org. "
        "Only fields you provide are changed — others remain at their current values. "
        "Requires admin permission."
    ),
)
async def update_eval_config(
    body: EvalConfigUpdate,
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    """Partially update org-level eval config overrides in org.settings."""
    _require_admin(api_key)
    org = await _get_org(db, api_key.org_id)

    # Deep-merge the incoming partial update into the existing org overrides
    current_overrides: Dict[str, Any] = org.settings.get("model_evaluation", {})
    new_overrides = _apply_eval_patch(current_overrides, body)

    # Write back to org.settings (preserve all other org settings)
    updated_settings = dict(org.settings or {})
    updated_settings["model_evaluation"] = new_overrides
    org.settings = updated_settings

    db.add(org)
    await db.commit()
    await db.refresh(org)

    # Return the resolved effective config after update
    config = resolve_eval_config(org)

    return {
        "success": True,
        "org_id": api_key.org_id,
        "message": "Evaluation settings updated",
        "effective_config": {
            "enabled": config.enabled,
            "mode": config.mode,
            "hallucination": {
                "enabled": config.hallucination.enabled,
                "method": config.hallucination.method,
                "judge_model": config.hallucination.judge_model,
                "threshold": config.hallucination.threshold,
                "on_flag": config.hallucination.on_flag,
            },
            "bias": {
                "enabled": config.bias.enabled,
                "method": config.bias.method,
                "threshold": config.bias.threshold,
                "on_flag": config.bias.on_flag,
                "categories": config.bias.categories,
            },
        },
    }


def _apply_eval_patch(
    current: Dict[str, Any],
    patch: EvalConfigUpdate,
) -> Dict[str, Any]:
    """
    Merge a partial EvalConfigUpdate onto the current org overrides dict.
    Only non-None fields in the patch are applied.
    """
    result = dict(current)

    if patch.enabled is not None:
        result["enabled"] = patch.enabled
    if patch.mode is not None:
        result["mode"] = patch.mode

    if patch.hallucination is not None:
        h = dict(result.get("hallucination", {}))
        p = patch.hallucination
        if p.enabled is not None:
            h["enabled"] = p.enabled
        if p.method is not None:
            h["method"] = p.method
        if p.judge_model is not None:
            h["judge_model"] = p.judge_model
        if p.threshold is not None:
            h["threshold"] = p.threshold
        if p.on_flag is not None:
            h["on_flag"] = p.on_flag
        result["hallucination"] = h

    if patch.bias is not None:
        b = dict(result.get("bias", {}))
        p = patch.bias
        if p.enabled is not None:
            b["enabled"] = p.enabled
        if p.method is not None:
            b["method"] = p.method
        if p.threshold is not None:
            b["threshold"] = p.threshold
        if p.on_flag is not None:
            b["on_flag"] = p.on_flag
        if p.categories is not None:
            b["categories"] = p.categories
        result["bias"] = b

    return result


# ── Standalone Evaluation Endpoint ────────────────────────────

class EvalRequest(BaseModel):
    prompt: str
    response: str
    hallucination_method: Literal["llm_judge", "grounding", "self_consistency"] = "llm_judge"
    bias_method: Literal["toxicity", "llm_judge", "both"] = "toxicity"
    hallucination_threshold: float = 0.75
    bias_threshold: float = 0.60


@router.post(
    "/me/evaluate",
    summary="Standalone Model Evaluation",
    description=(
        "Evaluate any prompt/response pair for hallucination and bias without proxying an LLM call. "
        "Useful for the UI playground and testing. Requires admin permission."
    ),
)
async def evaluate_response(
    body: EvalRequest,
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    """Run hallucination + bias evaluation on a given prompt/response pair."""
    _require_admin(api_key)

    from evaluation.eval_config import EvalConfig, HallucinationConfig, BiasConfig
    from evaluation.eval_runner import eval_runner
    import time

    start = time.monotonic()

    eval_config = EvalConfig(
        enabled=True,
        mode="inline",
        hallucination=HallucinationConfig(
            enabled=True,
            method=body.hallucination_method,
            threshold=body.hallucination_threshold,
            on_flag="warn",
        ),
        bias=BiasConfig(
            enabled=True,
            method=body.bias_method,
            threshold=body.bias_threshold,
            on_flag="warn",
        ),
    )

    result = await eval_runner.run(
        prompt=body.prompt,
        response=body.response,
        eval_config=eval_config,
    )

    latency_ms = round((time.monotonic() - start) * 1000, 2)

    return {
        "success": True,
        "latency_ms": latency_ms,
        "hallucination": result.hallucination.to_dict() if result.hallucination else None,
        "bias": result.bias.to_dict() if result.bias else None,
    }
