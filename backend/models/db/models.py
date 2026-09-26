"""
ORM Models — AI Governance & Security Layer API
SQLAlchemy models for all database entities.
"""
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Organizations (Multi-Tenant) ──────────────────────────────
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="free")  # free | pro | enterprise
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    users: Mapped[list["User"]] = relationship("User", back_populates="organization")
    api_keys: Mapped[list["ApiKey"]] = relationship("ApiKey", back_populates="organization")
    policies: Mapped[list["Policy"]] = relationship("Policy", back_populates="organization")
    provider_configs: Mapped[list["ProviderConfig"]] = relationship("ProviderConfig", back_populates="organization")


# ── Users ──────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "developer", "viewer", "compliance_officer", name="user_role"),
        default="developer"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    api_keys: Mapped[list["ApiKey"]] = relationship("ApiKey", back_populates="user")

    __table_args__ = (Index("idx_users_email", "email"),)


# ── API Keys ───────────────────────────────────────────────────
class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)   # First 8 chars (visible)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)         # ["proxy", "read:audit", ...]
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)      # [] = all allowed
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, default=60)
    daily_token_limit: Mapped[int] = mapped_column(Integer, default=1_000_000)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="api_keys")
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    __table_args__ = (Index("idx_api_keys_hash", "key_hash"),)


# ── Provider Configurations ────────────────────────────────────
class ProviderConfig(Base):
    __tablename__ = "provider_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)    # openai | anthropic | gemini ...
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_api_key: Mapped[str] = mapped_column(Text, nullable=False)
    extra_config: Mapped[dict] = mapped_column(JSON, default=dict)        # base_url, api_version, etc.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="provider_configs")


# ── Policies ───────────────────────────────────────────────────
class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    template: Mapped[str | None] = mapped_column(String(100), nullable=True)  # gdpr | hipaa | pci_dss | soc2
    priority: Mapped[int] = mapped_column(Integer, default=100)               # Lower = higher priority
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    applies_to: Mapped[dict] = mapped_column(JSON, default=dict)              # {users:[], api_keys:[], models:[]}
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="policies")
    rules: Mapped[list["PolicyRule"]] = relationship("PolicyRule", back_populates="policy", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_policies_org_active", "org_id", "is_active"),)


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    policy_id: Mapped[str] = mapped_column(String(36), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)    # pii | injection | content | quota | routing
    action: Mapped[str] = mapped_column(String(50), nullable=False)       # allow | block | mask | warn | redirect
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)          # Rule DSL conditions
    config: Mapped[dict] = mapped_column(JSON, default=dict)              # Rule-specific config
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    order: Mapped[int] = mapped_column(Integer, default=0)

    policy: Mapped["Policy"] = relationship("Policy", back_populates="rules")


# ── Audit Logs ─────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Request details
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, default=new_uuid)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)

    # Pipeline decisions
    pii_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    pii_entities: Mapped[list] = mapped_column(JSON, default=list)
    injection_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_score: Mapped[float] = mapped_column(Float, default=0.0)
    content_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    content_categories: Mapped[list] = mapped_column(JSON, default=list)
    policy_applied: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_action: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Response metrics
    status: Mapped[str] = mapped_column(String(50), nullable=False)       # success | blocked | error
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    # Optionally stored bodies
    request_body: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_body: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Model evaluation results (supplementary — updated async after request completes)
    hallucination_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    hallucination_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    bias_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    bias_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    eval_mode: Mapped[str | None] = mapped_column(String(50), nullable=True)  # inline | async | disabled

    # Immutability hash (SHA-256 of row content)
    integrity_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    __table_args__ = (
        Index("idx_audit_org_ts", "org_id", "timestamp"),
        Index("idx_audit_api_key", "api_key_id"),
        Index("idx_audit_request_id", "request_id"),
    )


# ── Security Incidents ─────────────────────────────────────────
class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False)
    audit_log_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False)  # pii_violation | injection_attempt | content_violation
    severity: Mapped[str] = mapped_column(String(50), nullable=False)         # low | medium | high | critical
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    __table_args__ = (Index("idx_incidents_org_type", "org_id", "incident_type"),)


# ── Usage Metrics (Daily Aggregates) ──────────────────────────
class UsageMetric(Base):
    __tablename__ = "usage_metrics"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    date: Mapped[str] = mapped_column(String(10), nullable=False)          # YYYY-MM-DD
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    successful_requests: Mapped[int] = mapped_column(Integer, default=0)
    blocked_requests: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    pii_detections: Mapped[int] = mapped_column(Integer, default=0)
    injection_attempts: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("idx_usage_org_date", "org_id", "date"),
    )
