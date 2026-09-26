"""
Auth API — AI Governance & Security Layer API
Login, token management, API key CRUD.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import (
    create_access_token,
    generate_api_key,
    get_current_user_from_jwt,
    hash_password,
    verify_password,
)
from models.db.models import ApiKey, Organization, User
from models.schemas.schemas import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)

router = APIRouter(prefix="/v1/auth", tags=["Auth"])


# ── Login ──────────────────────────────────────────────────────
@router.post("/token", response_model=TokenResponse, summary="Login and get JWT token")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is inactive")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token({"sub": user.id, "org_id": user.org_id, "role": user.role})
    return TokenResponse(
        access_token=token,
        expires_in=86400,  # 24 hours
    )


# ── User Registration (for initial setup) ─────────────────────
@router.post("/register", response_model=UserResponse, summary="Register a new user")
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create default org if needed (simplified for Phase 1)
    org_result = await db.execute(select(Organization).limit(1))
    org = org_result.scalar_one_or_none()

    if not org:
        org = Organization(
            name="Default Organization",
            slug="default",
        )
        db.add(org)
        await db.flush()

    user = User(
        org_id=org.id,
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ── API Key Management ─────────────────────────────────────────
@router.post("/api-keys", response_model=ApiKeyCreatedResponse, summary="Create a new API key")
async def create_api_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    full_key, key_prefix, key_hash = generate_api_key()

    api_key = ApiKey(
        org_id=current_user.org_id,
        user_id=current_user.id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        permissions=body.permissions,
        allowed_models=body.allowed_models,
        rate_limit_rpm=body.rate_limit_rpm,
        daily_token_limit=body.daily_token_limit,
        expires_at=body.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return ApiKeyCreatedResponse(
        **ApiKeyResponse.model_validate(api_key).model_dump(),
        api_key=full_key,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse], summary="List API keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.org_id == current_user.org_id,
            ApiKey.is_active == True,
        )
    )
    return result.scalars().all()


@router.delete("/api-keys/{key_id}", summary="Revoke an API key")
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user_from_jwt),
):
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.org_id == current_user.org_id,
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    await db.commit()
    return {"message": f"API key '{api_key.name}' revoked successfully"}


@router.get("/me", response_model=UserResponse, summary="Get current user info")
async def get_me(current_user=Depends(get_current_user_from_jwt)):
    return current_user
