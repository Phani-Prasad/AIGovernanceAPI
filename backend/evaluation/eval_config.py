"""
Eval Config — AI Governance & Security Layer API

Resolves the effective evaluation configuration for a given org by deep-merging
global defaults (from core/config.py env-vars) with per-org overrides stored in
Organization.settings["model_evaluation"].

Priority: org.settings > global env-var defaults
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Literal, Optional

from core.config import settings


# ── Sub-configs ────────────────────────────────────────────────

@dataclass
class HallucinationConfig:
    enabled: bool = True
    method: Literal["llm_judge", "self_consistency", "grounding"] = "llm_judge"
    judge_model: str = "gpt-4o-mini"
    threshold: float = 0.75
    on_flag: Literal["block", "warn", "log_only"] = "warn"


@dataclass
class BiasConfig:
    enabled: bool = True
    method: Literal["toxicity", "llm_judge", "both"] = "toxicity"
    threshold: float = 0.60
    on_flag: Literal["block", "warn", "log_only"] = "warn"
    categories: list = field(default_factory=lambda: [
        "toxicity", "severe_toxicity", "identity_attack", "insult", "threat"
    ])


@dataclass
class EvalConfig:
    enabled: bool = False
    mode: Literal["inline", "async", "disabled"] = "async"
    hallucination: HallucinationConfig = field(default_factory=HallucinationConfig)
    bias: BiasConfig = field(default_factory=BiasConfig)


# ── Resolver ───────────────────────────────────────────────────

def resolve_eval_config(org=None) -> EvalConfig:
    """
    Build the effective EvalConfig for a given org.

    Steps:
    1. Start from global env-var defaults (settings.get_eval_defaults)
    2. Deep-merge with org.settings["model_evaluation"] if present
    3. Return a validated EvalConfig dataclass

    Args:
        org: Optional Organization ORM instance. Pass None to get pure defaults.
    """
    # Step 1: Global defaults
    defaults: Dict[str, Any] = settings.get_eval_defaults.copy()

    # Step 2: Org-level overrides
    org_overrides: Dict[str, Any] = {}
    if org is not None and isinstance(getattr(org, "settings", None), dict):
        org_overrides = org.settings.get("model_evaluation", {})

    merged = _deep_merge(defaults, org_overrides)

    # Step 3: Build typed config
    h_cfg_raw = merged.get("hallucination", {})
    b_cfg_raw = merged.get("bias", {})

    hallucination = HallucinationConfig(
        enabled=h_cfg_raw.get("enabled", True),
        method=h_cfg_raw.get("method", "llm_judge"),
        judge_model=h_cfg_raw.get("judge_model", "gpt-4o-mini"),
        threshold=float(h_cfg_raw.get("threshold", 0.75)),
        on_flag=h_cfg_raw.get("on_flag", "warn"),
    )

    bias = BiasConfig(
        enabled=b_cfg_raw.get("enabled", True),
        method=b_cfg_raw.get("method", "toxicity"),
        threshold=float(b_cfg_raw.get("threshold", 0.60)),
        on_flag=b_cfg_raw.get("on_flag", "warn"),
        categories=b_cfg_raw.get("categories", [
            "toxicity", "severe_toxicity", "identity_attack", "insult", "threat"
        ]),
    )

    return EvalConfig(
        enabled=merged.get("enabled", False),
        mode=merged.get("mode", "async"),
        hallucination=hallucination,
        bias=bias,
    )


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge override into base.
    Override values take precedence; nested dicts are merged, not replaced.
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
