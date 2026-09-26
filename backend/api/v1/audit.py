"""
Audit & Dashboard API — AI Governance & Security Layer API
Audit log queries and real-time dashboard metrics.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import get_current_user_from_jwt
from models.db.models import AuditLog, SecurityIncident, ApiKey, Policy
from models.schemas.schemas import AuditLogResponse, DashboardStats

router = APIRouter(tags=["Audit & Dashboard"])


# ── Audit Logs ─────────────────────────────────────────────────
@router.get("/v1/audit", response_model=list[AuditLogResponse], summary="Query audit logs")
async def query_audit_logs(
    provider: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    pii_detected: Optional[bool] = Query(None),
    injection_detected: Optional[bool] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    query = select(AuditLog).where(AuditLog.org_id == current_user.org_id)

    if provider:
        query = query.where(AuditLog.provider == provider)
    if model:
        query = query.where(AuditLog.model == model)
    if status:
        query = query.where(AuditLog.status == status)
    if pii_detected is not None:
        query = query.where(AuditLog.pii_detected == pii_detected)
    if injection_detected is not None:
        query = query.where(AuditLog.injection_detected == injection_detected)
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)

    query = query.order_by(desc(AuditLog.timestamp)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/v1/audit/{log_id}", response_model=AuditLogResponse, summary="Get audit log by ID")
async def get_audit_log(
    log_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    from fastapi import HTTPException
    result = await db.execute(
        select(AuditLog).where(AuditLog.id == log_id, AuditLog.org_id == current_user.org_id)
    )
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return log


# ── Security Incidents ─────────────────────────────────────────
@router.get("/v1/security/incidents", summary="List security incidents")
async def list_incidents(
    incident_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    resolved: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    query = select(SecurityIncident).where(SecurityIncident.org_id == current_user.org_id)

    if incident_type:
        query = query.where(SecurityIncident.incident_type == incident_type)
    if severity:
        query = query.where(SecurityIncident.severity == severity)
    if resolved is not None:
        query = query.where(SecurityIncident.resolved == resolved)

    query = query.order_by(desc(SecurityIncident.created_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()

    return {
        "incidents": [
            {
                "id": i.id,
                "type": i.incident_type,
                "severity": i.severity,
                "description": i.description,
                "details": i.details,
                "resolved": i.resolved,
                "created_at": i.created_at,
            }
            for i in incidents
        ]
    }


# ── Dashboard Stats ────────────────────────────────────────────
@router.get("/v1/dashboard/stats", response_model=DashboardStats, summary="Get dashboard statistics")
async def get_dashboard_stats(
    period_days: int = Query(7, ge=1, le=90, description="Stats period in days"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    since = datetime.now(timezone.utc) - timedelta(days=period_days)
    org_id = current_user.org_id

    # Fetch raw rows and aggregate in Python (SQLite + Postgres compatible)
    result = await db.execute(
        select(
            AuditLog.status,
            AuditLog.total_tokens,
            AuditLog.estimated_cost_usd,
            AuditLog.latency_ms,
            AuditLog.pii_detected,
            AuditLog.injection_detected,
        ).where(
            AuditLog.org_id == org_id,
            AuditLog.timestamp >= since,
        )
    )
    rows = result.all()

    total = len(rows)
    successful = sum(1 for r in rows if r.status == "success")
    blocked = sum(1 for r in rows if r.status == "blocked")
    total_tokens = sum(r.total_tokens or 0 for r in rows)
    total_cost = sum(r.estimated_cost_usd or 0.0 for r in rows)
    avg_latency = (sum(r.latency_ms or 0.0 for r in rows) / total) if total > 0 else 0.0
    pii_count = sum(1 for r in rows if r.pii_detected)
    injection_count = sum(1 for r in rows if r.injection_detected)

    # Count active policies and keys
    policy_count_result = await db.execute(
        select(func.count(Policy.id)).where(Policy.org_id == org_id, Policy.is_active == True)
    )
    key_count_result = await db.execute(
        select(func.count(ApiKey.id)).where(ApiKey.org_id == org_id, ApiKey.is_active == True)
    )

    return DashboardStats(
        total_requests=total,
        successful_requests=successful,
        blocked_requests=blocked,
        total_tokens=total_tokens,
        total_cost_usd=round(total_cost, 4),
        avg_latency_ms=round(avg_latency, 2),
        pii_detections=pii_count,
        injection_attempts=injection_count,
        active_policies=int(policy_count_result.scalar() or 0),
        active_api_keys=int(key_count_result.scalar() or 0),
    )



@router.get("/v1/dashboard/usage-trend", summary="Get usage trend over time")
async def get_usage_trend(
    period_days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    """Get daily request counts for charting."""
    since = datetime.now(timezone.utc) - timedelta(days=period_days)

    result = await db.execute(
        select(
            AuditLog.timestamp,
            AuditLog.status,
            AuditLog.total_tokens,
        )
        .where(AuditLog.org_id == current_user.org_id, AuditLog.timestamp >= since)
        .order_by(AuditLog.timestamp)
    )
    rows = result.all()

    # Aggregate by date in Python (SQLite + Postgres compatible)
    daily: dict = {}
    for r in rows:
        date_str = r.timestamp.strftime("%Y-%m-%d") if r.timestamp else "unknown"
        if date_str not in daily:
            daily[date_str] = {"total": 0, "blocked": 0, "tokens": 0}
        daily[date_str]["total"] += 1
        if r.status == "blocked":
            daily[date_str]["blocked"] += 1
        daily[date_str]["tokens"] += r.total_tokens or 0

    return {
        "period_days": period_days,
        "data": [
            {
                "date": date,
                "total_requests": v["total"],
                "blocked_requests": v["blocked"],
                "tokens": v["tokens"],
            }
            for date, v in sorted(daily.items())
        ],
    }
