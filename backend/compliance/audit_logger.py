"""
Audit Logger — AI Governance & Security Layer API
Immutable audit trail with integrity hashing for all LLM requests.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.db.models import AuditLog, SecurityIncident
from models.schemas.schemas import PipelineResult


def _compute_integrity_hash(data: Dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of audit log entry for tamper detection.
    Excludes the hash field itself.
    """
    serializable = {
        k: str(v) if not isinstance(v, (str, int, float, bool, list, dict, type(None))) else v
        for k, v in data.items()
        if k != "integrity_hash"
    }
    canonical = json.dumps(serializable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLogger:
    """
    Immutable audit logger for all LLM requests passing through
    the governance layer.
    """

    async def log_request(
        self,
        db: AsyncSession,
        *,
        org_id: str,
        api_key_id: Optional[str],
        user_id: Optional[str],
        request_id: str,
        provider: str,
        model: str,
        endpoint: str,
        pipeline_result: PipelineResult,
        status: str,
        status_code: int,
        latency_ms: float,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
        request_body: Optional[Dict] = None,
        response_body: Optional[Dict] = None,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """
        Create an immutable audit log entry.
        Computes an integrity hash for tamper detection.
        """
        log_data = {
            "org_id": org_id,
            "api_key_id": api_key_id,
            "user_id": user_id,
            "request_id": request_id,
            "provider": provider,
            "model": model,
            "endpoint": endpoint,
            "pii_detected": pipeline_result.pii.detected,
            "pii_entities": [e.model_dump() for e in pipeline_result.pii.entities],
            "injection_detected": pipeline_result.injection.detected,
            "injection_score": pipeline_result.injection.score,
            "content_flagged": pipeline_result.content.flagged,
            "content_categories": list(pipeline_result.content.categories.keys()),
            "policy_applied": pipeline_result.policy_applied,
            "policy_action": pipeline_result.policy_action,
            "status": status,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": estimated_cost_usd,
            "ip_address": ip_address,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Compute integrity hash
        integrity_hash = _compute_integrity_hash(log_data)

        audit_entry = AuditLog(
            **{k: v for k, v in log_data.items() if k != "timestamp"},
            request_body=request_body if settings.log_request_body else None,
            response_body=response_body if settings.log_response_body else None,
            error_message=error_message,
            user_agent=user_agent,
            integrity_hash=integrity_hash,
        )

        db.add(audit_entry)

        # Log security incidents for flagged requests
        if pipeline_result.pii.detected and pipeline_result.pii.action_taken == "blocked":
            await self._create_incident(db, org_id, audit_entry.id, "pii_violation", "medium",
                                        f"PII blocked in request to {model}",
                                        {"entities": [e.type for e in pipeline_result.pii.entities]})

        if pipeline_result.injection.detected and pipeline_result.injection.action_taken == "blocked":
            severity = "high" if pipeline_result.injection.score > 0.85 else "medium"
            await self._create_incident(db, org_id, audit_entry.id, "injection_attempt", severity,
                                        f"Prompt injection blocked (score: {pipeline_result.injection.score:.2f})",
                                        {"patterns": pipeline_result.injection.patterns_matched,
                                         "score": pipeline_result.injection.score})

        if pipeline_result.content.flagged and pipeline_result.content.action_taken == "blocked":
            await self._create_incident(db, org_id, audit_entry.id, "content_violation", "high",
                                        f"Content policy violation for {model}",
                                        {"categories": pipeline_result.content.categories})

        return audit_entry

    async def update_eval_result(
        self,
        db: AsyncSession,
        *,
        audit_log_id: str,
        eval_result: Any,
    ) -> None:
        """
        Patch eval scores onto an existing AuditLog row (async mode).

        This is a targeted UPDATE — it does NOT recompute the integrity hash.
        Eval scores are treated as supplementary, append-only fields so the
        immutability of the core audit record is preserved.

        Args:
            db:            Active async DB session (caller must commit).
            audit_log_id:  Primary key of the AuditLog row to update.
            eval_result:   EvalResult instance from eval_runner.
        """
        from sqlalchemy import update as sa_update
        from models.db.models import AuditLog

        values: Dict[str, Any] = {
            "eval_mode": eval_result.eval_mode,
        }

        if eval_result.hallucination:
            values["hallucination_score"] = eval_result.hallucination.score
            values["hallucination_flagged"] = eval_result.hallucination.flagged

        if eval_result.bias:
            values["bias_score"] = eval_result.bias.score
            values["bias_flagged"] = eval_result.bias.flagged

        stmt = (
            sa_update(AuditLog)
            .where(AuditLog.id == audit_log_id)
            .values(**values)
        )
        await db.execute(stmt)

    async def _create_incident(
        self,
        db: AsyncSession,
        org_id: str,
        audit_log_id: str,
        incident_type: str,
        severity: str,
        description: str,
        details: Dict,
    ) -> None:
        incident = SecurityIncident(
            org_id=org_id,
            audit_log_id=audit_log_id,
            incident_type=incident_type,
            severity=severity,
            description=description,
            details=details,
        )
        db.add(incident)

    def verify_integrity(self, audit_log: AuditLog) -> bool:
        """Verify the integrity hash of an audit log entry."""
        data = {
            "org_id": audit_log.org_id,
            "api_key_id": audit_log.api_key_id,
            "user_id": audit_log.user_id,
            "request_id": audit_log.request_id,
            "provider": audit_log.provider,
            "model": audit_log.model,
            "endpoint": audit_log.endpoint,
            "pii_detected": audit_log.pii_detected,
            "pii_entities": audit_log.pii_entities,
            "injection_detected": audit_log.injection_detected,
            "injection_score": audit_log.injection_score,
            "content_flagged": audit_log.content_flagged,
            "content_categories": audit_log.content_categories,
            "policy_applied": audit_log.policy_applied,
            "policy_action": audit_log.policy_action,
            "status": audit_log.status,
            "status_code": audit_log.status_code,
            "latency_ms": audit_log.latency_ms,
            "prompt_tokens": audit_log.prompt_tokens,
            "completion_tokens": audit_log.completion_tokens,
            "total_tokens": audit_log.total_tokens,
            "estimated_cost_usd": audit_log.estimated_cost_usd,
            "ip_address": audit_log.ip_address,
            "timestamp": audit_log.timestamp.isoformat(),
        }
        expected_hash = _compute_integrity_hash(data)
        return expected_hash == audit_log.integrity_hash


# ── Singleton ──────────────────────────────────────────────────
audit_logger = AuditLogger()
