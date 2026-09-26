"""
Policies API — AI Governance & Security Layer API
CRUD for governance policies and templates.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import get_current_user_from_jwt
from governance.policy_engine import policy_engine, POLICY_TEMPLATES
from models.db.models import Policy, PolicyRule
from models.schemas.schemas import PolicyCreate, PolicyResponse

router = APIRouter(prefix="/v1/policies", tags=["Policies"])


@router.get("", response_model=list[PolicyResponse], summary="List all policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(Policy).where(Policy.org_id == current_user.org_id).order_by(Policy.priority)
    )
    return result.scalars().all()


@router.get("/templates", summary="List built-in policy templates")
async def list_templates():
    return {
        "templates": [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in POLICY_TEMPLATES.items()
        ]
    }


@router.post("", response_model=PolicyResponse, summary="Create a new policy")
async def create_policy(
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    # If using a template, merge template rules with any custom rules
    rules_data = list(body.rules)
    if body.template:
        template = POLICY_TEMPLATES.get(body.template)
        if not template:
            raise HTTPException(status_code=400, detail=f"Unknown template: {body.template}")
        # Template rules as base, user rules override
        template_rules = [PolicyCreate.model_validate({"name": "x", "rules": []}).model_fields]
        rules_data = template["rules"] + [r.model_dump() for r in body.rules]

    policy = Policy(
        org_id=current_user.org_id,
        name=body.name,
        description=body.description,
        template=body.template,
        priority=body.priority,
        applies_to=body.applies_to,
    )
    db.add(policy)
    await db.flush()

    # Create rules
    for i, rule_data in enumerate(rules_data):
        rule_dict = rule_data if isinstance(rule_data, dict) else rule_data.model_dump()
        rule = PolicyRule(
            policy_id=policy.id,
            rule_type=rule_dict.get("rule_type", "pii"),
            action=rule_dict.get("action", "mask"),
            conditions=rule_dict.get("conditions", {}),
            config=rule_dict.get("config", {}),
            order=rule_dict.get("order", i),
        )
        db.add(rule)

    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/{policy_id}", response_model=PolicyResponse, summary="Get policy by ID")
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.patch("/{policy_id}/toggle", summary="Enable or disable a policy")
async def toggle_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy.is_active = not policy.is_active
    await db.commit()
    return {"id": policy.id, "is_active": policy.is_active, "message": f"Policy {'enabled' if policy.is_active else 'disabled'}"}


@router.delete("/{policy_id}", summary="Delete a policy")
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    await db.delete(policy)
    await db.commit()
    return {"message": f"Policy '{policy.name}' deleted"}
