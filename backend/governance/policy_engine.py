"""
Policy Engine — AI Governance & Security Layer API
Rule-based policy evaluation for all LLM requests.
"""
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.db.models import Policy, PolicyRule
from models.schemas.schemas import (
    ContentModerationResult,
    InjectionScanResult,
    PIIScanResult,
    PipelineResult,
)

# ── Built-in Policy Templates ──────────────────────────────────
POLICY_TEMPLATES: Dict[str, Dict] = {
    "gdpr": {
        "name": "GDPR Compliance",
        "description": "General Data Protection Regulation compliance policy",
        "rules": [
            {"rule_type": "pii", "action": "block", "config": {"entities": ["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER", "IP_ADDRESS", "LOCATION"]}, "order": 1},
            {"rule_type": "content", "action": "block", "config": {"categories": ["personal_data_exposure"]}, "order": 2},
        ],
    },
    "hipaa": {
        "name": "HIPAA Healthcare",
        "description": "Health Insurance Portability and Accountability Act compliance",
        "rules": [
            {"rule_type": "pii", "action": "block", "config": {"entities": ["PERSON", "DATE_TIME", "MEDICAL_LICENSE", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION"]}, "order": 1},
            {"rule_type": "injection", "action": "block", "config": {"sensitivity": "high"}, "order": 2},
        ],
    },
    "pci_dss": {
        "name": "PCI-DSS Financial",
        "description": "Payment Card Industry Data Security Standard compliance",
        "rules": [
            {"rule_type": "pii", "action": "block", "config": {"entities": ["CREDIT_CARD", "US_BANK_NUMBER", "IBAN_CODE"]}, "order": 1},
            {"rule_type": "content", "action": "block", "config": {"categories": ["financial_data"]}, "order": 2},
        ],
    },
    "soc2": {
        "name": "SOC 2",
        "description": "Service Organization Control 2 compliance",
        "rules": [
            {"rule_type": "pii", "action": "mask", "config": {}, "order": 1},
            {"rule_type": "injection", "action": "block", "config": {"sensitivity": "medium"}, "order": 2},
        ],
    },
    "enterprise": {
        "name": "Enterprise Security",
        "description": "Enterprise-grade security policy with all protections enabled",
        "rules": [
            {"rule_type": "pii", "action": "mask", "config": {}, "order": 1},
            {"rule_type": "injection", "action": "block", "config": {"sensitivity": "high"}, "order": 2},
            {"rule_type": "content", "action": "block", "config": {}, "order": 3},
            {"rule_type": "hallucination", "action": "warn", "config": {"threshold": 0.75}, "order": 4},
            {"rule_type": "bias", "action": "warn", "config": {"threshold": 0.60}, "order": 5},
        ],
    },
}


class PolicyEngine:
    """
    Evaluates active policies against the security pipeline results
    and determines the final action for each request.
    """

    async def evaluate(
        self,
        db: AsyncSession,
        org_id: str,
        api_key_id: Optional[str],
        pipeline_result: PipelineResult,
        model: str,
    ) -> PipelineResult:
        """
        Apply all active policies for the org to the pipeline result.
        Policies are evaluated in priority order (lower number = higher priority).
        Returns the updated PipelineResult with policy decisions applied.
        """
        # Load active policies for the org
        policies = await self._load_policies(db, org_id)

        for policy in policies:
            action, reason = await self._evaluate_policy(policy, pipeline_result, model)
            if action and action != "allow":
                pipeline_result.policy_applied = policy.id
                pipeline_result.policy_action = action
                if action == "block":
                    pipeline_result.blocked = True
                    pipeline_result.block_reason = reason or f"Blocked by policy: {policy.name}"
                break  # First matching blocking policy wins

        return pipeline_result

    async def _load_policies(self, db: AsyncSession, org_id: str) -> List[Policy]:
        """Load active policies ordered by priority."""
        from sqlalchemy.orm import selectinload
        result = await db.execute(
            select(Policy)
            .options(selectinload(Policy.rules))
            .where(Policy.org_id == org_id, Policy.is_active == True)
            .order_by(Policy.priority.asc())
        )
        return list(result.scalars().all())

    async def _evaluate_policy(
        self,
        policy: Policy,
        pipeline_result: PipelineResult,
        model: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Evaluate a single policy against pipeline results.
        Returns (action, reason) tuple.
        """
        rules = sorted(policy.rules or [], key=lambda r: r.order)

        for rule in rules:
            if not rule.is_active:
                continue

            action, reason = self._evaluate_rule(rule, pipeline_result)
            if action:
                return action, reason

        return None, None

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        pipeline_result: PipelineResult,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Evaluate a single rule against pipeline results."""

        if rule.rule_type == "pii":
            if pipeline_result.pii.detected:
                target_entities = rule.config.get("entities", [])
                if not target_entities:
                    return rule.action, f"PII detected: {[e.type for e in pipeline_result.pii.entities]}"
                # Check if any detected entity matches the rule's entity list
                detected_types = {e.type for e in pipeline_result.pii.entities}
                if detected_types & set(target_entities):
                    return rule.action, f"PII entities detected: {list(detected_types & set(target_entities))}"

        elif rule.rule_type == "injection":
            if pipeline_result.injection.detected:
                min_score = rule.config.get("min_score", 0.0)
                if pipeline_result.injection.score >= min_score:
                    return rule.action, f"Injection attempt (score: {pipeline_result.injection.score:.2f})"

        elif rule.rule_type == "content":
            if pipeline_result.content.flagged:
                categories = rule.config.get("categories", [])
                if not categories:
                    return rule.action, f"Content flagged: {list(pipeline_result.content.categories.keys())}"
                flagged_cats = set(pipeline_result.content.categories.keys())
                if flagged_cats & set(categories):
                    return rule.action, f"Content categories: {list(flagged_cats & set(categories))}"

        elif rule.rule_type == "hallucination":
            # Only evaluated when pipeline_result.evaluation is populated (inline mode)
            if pipeline_result.evaluation and pipeline_result.evaluation.hallucination:
                h = pipeline_result.evaluation.hallucination
                threshold = rule.config.get("threshold", 0.75)
                if h.flagged or h.score >= threshold:
                    return rule.action, f"Hallucination risk detected (score: {h.score:.2f})"

        elif rule.rule_type == "bias":
            # Only evaluated when pipeline_result.evaluation is populated (inline mode)
            if pipeline_result.evaluation and pipeline_result.evaluation.bias:
                b = pipeline_result.evaluation.bias
                threshold = rule.config.get("threshold", 0.60)
                target_cats = rule.config.get("categories", [])
                if b.flagged or b.score >= threshold:
                    if not target_cats or set(b.categories.keys()) & set(target_cats):
                        return rule.action, f"Bias/toxicity detected (score: {b.score:.2f})"

        return None, None

    def get_template(self, template_name: str) -> Optional[Dict]:
        """Get a built-in policy template by name."""
        return POLICY_TEMPLATES.get(template_name)

    def list_templates(self) -> List[str]:
        return list(POLICY_TEMPLATES.keys())


# ── Singleton ──────────────────────────────────────────────────
policy_engine = PolicyEngine()
