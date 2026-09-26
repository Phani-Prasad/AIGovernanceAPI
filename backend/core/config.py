"""
Core Configuration — AI Governance & Security Layer API
Pydantic-based settings management with environment variable support.
"""
from functools import lru_cache
from typing import Any, Dict, List, Literal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────
    app_name: str = "AI Governance API"
    app_version: str = "1.0.0"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # ── Security ──────────────────────────────────────────────
    secret_key: str = "dev-secret-key-change-in-production-min-32-chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440
    api_key_prefix: str = "gvn_"

    # ── Database ──────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./ai_governance.db"

    # ── Redis ─────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── CORS ──────────────────────────────────────────────────
    allowed_origins: str = "http://localhost:3000,http://localhost:8080,http://localhost:5173,http://localhost:8000"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    # ── LLM Provider Keys ─────────────────────────────────────
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    groq_api_key: str = ""
    azure_api_key: str = ""
    azure_api_base: str = ""
    azure_api_version: str = "2024-02-15-preview"
    cohere_api_key: str = ""

    # ── Security Pipeline ─────────────────────────────────────
    pii_detection_enabled: bool = True
    pii_action: Literal["detect", "mask", "block"] = "mask"
    injection_detection_enabled: bool = True
    injection_sensitivity: Literal["low", "medium", "high", "strict"] = "medium"
    content_moderation_enabled: bool = True

    # ── Rate Limiting ─────────────────────────────────────────
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_tokens_per_day: int = 1_000_000

    # ── Audit ─────────────────────────────────────────────────
    audit_log_enabled: bool = True
    audit_log_retention_days: int = 90
    log_request_body: bool = True
    log_response_body: bool = False

    # ── Model Evaluation ──────────────────────────────────────
    # Global defaults — any org can override via org.settings["model_evaluation"]
    eval_enabled: bool = False
    eval_mode: Literal["inline", "async", "disabled"] = "async"

    # Hallucination detection
    eval_hallucination_enabled: bool = True
    eval_hallucination_method: Literal["llm_judge", "self_consistency", "grounding"] = "llm_judge"
    eval_hallucination_judge_model: str = "gpt-4o-mini"
    eval_hallucination_threshold: float = 0.75
    eval_hallucination_on_flag: Literal["block", "warn", "log_only"] = "warn"

    # Bias / toxicity detection
    eval_bias_enabled: bool = True
    eval_bias_method: Literal["toxicity", "llm_judge", "both"] = "toxicity"
    eval_bias_threshold: float = 0.60
    eval_bias_on_flag: Literal["block", "warn", "log_only"] = "warn"

    @property
    def get_eval_defaults(self) -> Dict[str, Any]:
        """Return eval global defaults as a plain dict for merging with org overrides."""
        return {
            "enabled": self.eval_enabled,
            "mode": self.eval_mode,
            "hallucination": {
                "enabled": self.eval_hallucination_enabled,
                "method": self.eval_hallucination_method,
                "judge_model": self.eval_hallucination_judge_model,
                "threshold": self.eval_hallucination_threshold,
                "on_flag": self.eval_hallucination_on_flag,
            },
            "bias": {
                "enabled": self.eval_bias_enabled,
                "method": self.eval_bias_method,
                "threshold": self.eval_bias_threshold,
                "on_flag": self.eval_bias_on_flag,
            },
        }

    # ── Admin ─────────────────────────────────────────────────
    admin_email: str = "admin@example.com"
    admin_password: str = "changeme123!"

    # ── Celery ────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()


settings = get_settings()
