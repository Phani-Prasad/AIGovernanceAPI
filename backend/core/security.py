"""
Security — AI Governance & Security Layer API
API key generation/validation, JWT handling, and RBAC.
"""
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db

# ── FastAPI Security Schemes ───────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-Governance-Key", auto_error=False)



# ── Password Hashing ───────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash password using bcrypt directly (avoids passlib 72-byte self-test bug)."""
    pwd_bytes = password[:72].encode("utf-8")
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    plain_bytes = plain[:72].encode("utf-8")
    hashed_bytes = hashed.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (full_key, key_prefix, key_hash)
    - full_key: returned once to the user (gvn_<32 random chars>)
    - key_prefix: first 8 chars after prefix (stored, for display)
    - key_hash: HMAC-SHA256 hash (stored in DB for validation)
    """
    random_part = secrets.token_urlsafe(32)
    full_key = f"{settings.api_key_prefix}{random_part}"
    key_prefix = full_key[:12]  # e.g. gvn_abc123
    key_hash = _hash_api_key(full_key)
    return full_key, key_prefix, key_hash


def _hash_api_key(key: str) -> str:
    """HMAC-SHA256 hash of the API key using the secret key."""
    return hmac.new(
        settings.secret_key.encode(),
        key.encode(),
        hashlib.sha256
    ).hexdigest()


def hash_api_key(key: str) -> str:
    """Public alias for hashing."""
    return _hash_api_key(key)


# ── JWT ────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Auth Dependencies ──────────────────────────────────────────
async def get_current_user_from_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """Validate JWT token and return current user."""
    from models.db.models import User

    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = decode_access_token(credentials.credentials)
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user


async def validate_api_key(
    raw_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
):
    """Validate X-Governance-Key header and return the ApiKey record."""
    from models.db.models import ApiKey

    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide X-Governance-Key header.",
        )

    key_hash = _hash_api_key(raw_key)
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    # Check expiry
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="API key has expired")

    # Update last used (non-blocking fire-and-forget style)
    api_key.last_used_at = datetime.now(timezone.utc)

    return api_key


# ── RBAC ───────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": ["*"],
    "developer": ["proxy", "read:audit", "read:policies", "read:metrics"],
    "compliance_officer": ["read:audit", "read:policies", "write:policies", "read:metrics", "read:incidents"],
    "viewer": ["read:audit", "read:metrics"],
}


def require_role(*roles: str):
    """FastAPI dependency to require specific user roles."""
    async def _check_role(user=Depends(get_current_user_from_jwt)):
        if user.role not in roles and "admin" not in roles:
            if user.role != "admin":
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{user.role}' not permitted. Required: {list(roles)}"
                )
        return user
    return _check_role


def require_permission(permission: str):
    """FastAPI dependency to require a specific permission on an API key."""
    async def _check_permission(api_key=Depends(validate_api_key)):
        perms = api_key.permissions or []
        if "*" not in perms and permission not in perms:
            raise HTTPException(
                status_code=403,
                detail=f"API key missing permission: {permission}"
            )
        return api_key
    return _check_permission
