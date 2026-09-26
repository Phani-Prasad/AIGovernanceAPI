"""
Eval Runner — AI Governance & Security Layer API

Orchestrates hallucination + bias detectors and dispatches results
back to the audit log (async mode) or returns them inline.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional

import structlog

from evaluation.eval_config import EvalConfig
from evaluation.hallucination_detector import HallucinationResult, hallucination_detector
from evaluation.bias_detector import BiasResult, bias_detector

logger = structlog.get_logger()


class EvalResult:
    """Combined result of hallucination + bias evaluation."""

    def __init__(
        self,
        hallucination: Optional[HallucinationResult] = None,
        bias: Optional[BiasResult] = None,
        eval_mode: str = "disabled",
        evaluated_at: Optional[datetime] = None,
    ):
        self.hallucination = hallucination
        self.bias = bias
        self.eval_mode = eval_mode
        self.evaluated_at = evaluated_at or datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "hallucination": self.hallucination.to_dict() if self.hallucination else None,
            "bias": self.bias.to_dict() if self.bias else None,
            "eval_mode": self.eval_mode,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class EvalRunner:
    """
    Orchestrates the model evaluation pipeline.

    Modes:
    - inline:   Awaits both detectors, returns EvalResult before response is sent.
    - async:    Fires asyncio.create_task(); response is sent immediately.
                The task opens a new DB session and updates the audit log row.
    - disabled: No-op.
    """

    async def run(
        self,
        prompt: str,
        response: str,
        eval_config: EvalConfig,
    ) -> EvalResult:
        """
        Run all enabled evaluators and return the combined result.
        Called directly for inline mode.
        """
        if not eval_config.enabled or eval_config.mode == "disabled":
            return EvalResult(eval_mode="disabled")

        h_result: Optional[HallucinationResult] = None
        b_result: Optional[BiasResult] = None

        # Run enabled detectors concurrently
        tasks = []
        if eval_config.hallucination.enabled:
            tasks.append(
                hallucination_detector.evaluate(prompt, response, eval_config.hallucination)
            )
        if eval_config.bias.enabled:
            tasks.append(
                bias_detector.evaluate(response, eval_config.bias)
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            idx = 0
            if eval_config.hallucination.enabled:
                r = results[idx]
                idx += 1
                if isinstance(r, Exception):
                    logger.error("Hallucination detector raised exception", error=str(r))
                    h_result = HallucinationResult(error=str(r))
                else:
                    h_result = r

            if eval_config.bias.enabled:
                r = results[idx]
                if isinstance(r, Exception):
                    logger.error("Bias detector raised exception", error=str(r))
                    b_result = BiasResult(error=str(r))
                else:
                    b_result = r

        return EvalResult(
            hallucination=h_result,
            bias=b_result,
            eval_mode=eval_config.mode,
        )

    def dispatch_async(
        self,
        audit_log_id: str,
        prompt: str,
        response: str,
        eval_config: EvalConfig,
    ) -> None:
        """
        Fire-and-forget async evaluation.
        Spawns a background task that runs eval and patches the audit log row.

        Args:
            audit_log_id: The ID of the AuditLog row to update after eval completes.
            prompt:       Original user prompt text.
            response:     LLM response text.
            eval_config:  Resolved EvalConfig for the org.
        """
        asyncio.create_task(
            self._async_eval_and_persist(audit_log_id, prompt, response, eval_config),
            name=f"eval-{audit_log_id[:8]}",
        )
        logger.info("Async model evaluation dispatched", audit_log_id=audit_log_id)

    async def _async_eval_and_persist(
        self,
        audit_log_id: str,
        prompt: str,
        response: str,
        eval_config: EvalConfig,
    ) -> None:
        """
        Background coroutine: run eval, then update the audit log row.
        Opens its own DB session (request session is already closed).
        """
        from core.database import AsyncSessionLocal
        from compliance.audit_logger import audit_logger as _audit_logger

        try:
            eval_result = await self.run(prompt, response, eval_config)

            async with AsyncSessionLocal() as db:
                await _audit_logger.update_eval_result(
                    db=db,
                    audit_log_id=audit_log_id,
                    eval_result=eval_result,
                )
                await db.commit()

            logger.info(
                "Async eval result persisted to audit log",
                audit_log_id=audit_log_id,
                hallucination_score=eval_result.hallucination.score if eval_result.hallucination else None,
                bias_score=eval_result.bias.score if eval_result.bias else None,
            )

        except Exception as e:
            logger.error(
                "Async eval task failed",
                audit_log_id=audit_log_id,
                error=str(e),
            )


# ── Singleton ──────────────────────────────────────────────────
eval_runner = EvalRunner()
