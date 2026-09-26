"""
Celery Worker — AI Governance & Security Layer API
Background task processing for reports, alerts, and async operations.
"""
from celery import Celery
from core.config import settings

celery_app = Celery(
    "ai_governance",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "tasks.celery_worker.generate_compliance_report": {"queue": "reports"},
        "tasks.celery_worker.send_security_alert": {"queue": "alerts"},
    },
)


@celery_app.task(name="tasks.celery_worker.generate_compliance_report")
def generate_compliance_report(org_id: str, report_type: str, period_days: int = 30):
    """Generate compliance report asynchronously."""
    # Placeholder for Phase 4 implementation
    return {"status": "queued", "org_id": org_id, "report_type": report_type}


@celery_app.task(name="tasks.celery_worker.send_security_alert")
def send_security_alert(org_id: str, incident_type: str, details: dict):
    """Send security alert notification asynchronously."""
    # Placeholder for Phase 4 implementation
    return {"status": "sent", "org_id": org_id, "incident_type": incident_type}


@celery_app.task(name="tasks.celery_worker.run_model_evaluation")
def run_model_evaluation(audit_log_id: str, prompt: str, response: str, eval_config_dict: dict):
    """
    Run hallucination + bias evaluation in a Celery worker and patch the audit log row.

    This is an alternative to asyncio.create_task() for environments where
    Celery/Redis infra is already running. Currently a stub — async mode via
    asyncio.create_task() in eval_runner.py is the primary mechanism.
    """
    # Placeholder — wired up when Celery infra is active
    return {"status": "queued", "audit_log_id": audit_log_id}
