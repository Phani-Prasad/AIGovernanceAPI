"""
Pydantic Schemas — AI Governance & Security Layer API
Request/response validation schemas for all API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Base ───────────────────────────────────────────────────────
class BaseResponse(BaseModel):
    success: bool = True
    message: str = "OK"


# ── Auth Schemas ───────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str
    role: Literal["admin", "developer", "viewer", "compliance_officer"] = "developer"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    org_id: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── API Key Schemas ────────────────────────────────────────────
class ApiKeyCreate(BaseModel):
    name: str = Field(max_length=255)
    permissions: List[str] = Field(default=["proxy"])
    allowed_models: List[str] = Field(default=[])
    rate_limit_rpm: int = Field(default=60, ge=1, le=10000)
    daily_token_limit: int = Field(default=1_000_000, ge=1000)
    expires_at: Optional[datetime] = None


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    permissions: List[str]
    rate_limit_rpm: int
    daily_token_limit: int
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Only returned once on creation — includes the full key."""
    api_key: str


# ── LLM Proxy Schemas ──────────────────────────────────────────
class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "function"]
    content: str | List[Dict[str, Any]]
    name: Optional[str] = None


class ProxyRequest(BaseModel):
    model: str = Field(description="Model identifier e.g. gpt-4o, claude-3-5-sonnet-20241022")
    messages: List[Message]
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1)
    stream: bool = False
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    stop: Optional[List[str]] = None
    user: Optional[str] = None
    # Governance metadata
    tags: Optional[Dict[str, str]] = Field(default=None, description="Custom metadata tags for audit")

    model_config = {"extra": "allow"}


class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class ProxyResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: UsageInfo
    # Governance metadata
    governance: Dict[str, Any] = Field(default_factory=dict)


# ── Security Pipeline Schemas ──────────────────────────────────
class PIIEntity(BaseModel):
    type: str           # PERSON, EMAIL_ADDRESS, PHONE_NUMBER, etc.
    start: int
    end: int
    score: float
    text: Optional[str] = None  # Only in detect mode


class PIIScanResult(BaseModel):
    detected: bool
    entities: List[PIIEntity] = []
    sanitized_text: Optional[str] = None
    action_taken: Literal["none", "masked", "blocked"]


class InjectionScanResult(BaseModel):
    detected: bool
    score: float = 0.0
    patterns_matched: List[str] = []
    action_taken: Literal["none", "blocked", "warned"]


class ContentModerationResult(BaseModel):
    flagged: bool
    categories: Dict[str, bool] = {}
    scores: Dict[str, float] = {}
    action_taken: Literal["none", "blocked", "warned"]


class PipelineResult(BaseModel):
    """Combined result of the full security pipeline."""
    request_id: str
    pii: PIIScanResult
    injection: InjectionScanResult
    content: ContentModerationResult
    evaluation: Optional["EvalResult"] = None   # populated post-response
    policy_applied: Optional[str] = None
    policy_action: Optional[str] = None
    blocked: bool = False
    block_reason: Optional[str] = None


# ── Model Evaluation Schemas ───────────────────────────────────
class HallucinationResult(BaseModel):
    score: float = 0.0          # 0.0 = grounded, 1.0 = hallucinated
    flagged: bool = False
    reasoning: Optional[str] = None
    method: str = "llm_judge"
    error: Optional[str] = None


class BiasResult(BaseModel):
    score: float = 0.0
    flagged: bool = False
    categories: Dict[str, float] = {}   # {"toxicity": 0.12, ...}
    method: str = "toxicity"
    error: Optional[str] = None


class EvalResult(BaseModel):
    hallucination: Optional[HallucinationResult] = None
    bias: Optional[BiasResult] = None
    eval_mode: str = "disabled"
    evaluated_at: Optional[datetime] = None


# ── Policy Schemas ─────────────────────────────────────────────
class PolicyRuleCreate(BaseModel):
    rule_type: Literal["pii", "injection", "content", "quota", "routing",
                       "hallucination", "bias"]
    action: Literal["allow", "block", "mask", "warn", "redirect"]
    conditions: Dict[str, Any] = {}
    config: Dict[str, Any] = {}
    order: int = 0


class PolicyCreate(BaseModel):
    name: str = Field(max_length=255)
    description: Optional[str] = None
    template: Optional[Literal["gdpr", "hipaa", "pci_dss", "soc2", "enterprise"]] = None
    priority: int = Field(default=100, ge=1, le=1000)
    applies_to: Dict[str, Any] = Field(default_factory=dict)
    rules: List[PolicyRuleCreate] = []


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    template: Optional[str]
    priority: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Audit Schemas ──────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    id: str
    request_id: str
    org_id: str
    provider: str
    model: str
    status: str
    status_code: int
    latency_ms: float
    total_tokens: int
    estimated_cost_usd: float
    pii_detected: bool
    injection_detected: bool
    content_flagged: bool
    policy_action: Optional[str]
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditQueryParams(BaseModel):
    org_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    status: Optional[str] = None
    pii_detected: Optional[bool] = None
    injection_detected: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


# ── Dashboard / Stats Schemas ──────────────────────────────────
class DashboardStats(BaseModel):
    total_requests: int
    successful_requests: int
    blocked_requests: int
    total_tokens: int
    total_cost_usd: float
    avg_latency_ms: float
    pii_detections: int
    injection_attempts: int
    active_policies: int
    active_api_keys: int


# ── Error Response ─────────────────────────────────────────────
class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None
