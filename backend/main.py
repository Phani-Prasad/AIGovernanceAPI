"""
AI Governance & Security Layer API
FastAPI Application Entry Point

Drop-in LLM proxy with enterprise-grade security, governance,
and compliance built-in.
"""
import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.database import close_db, init_db

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


# ── Lifespan (startup/shutdown) ────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AI Governance API", version=settings.app_version, env=settings.app_env)

    # Initialize database tables
    await init_db()
    logger.info("Database initialized")

    # Seed default admin user if needed
    await _seed_admin()
    logger.info("Startup complete — governance layer active")

    yield

    # Shutdown
    await close_db()
    logger.info("AI Governance API shutdown complete")


# ── FastAPI App ────────────────────────────────────────────────
app = FastAPI(
    title="AI Governance & Security Layer API",
    description="""
## 🛡️ AI Governance & Security Layer

A plug-and-play, LLM-agnostic middleware that adds enterprise-grade
security and governance to any AI application.

### Key Features
- **Drop-in proxy** — OpenAI-compatible endpoint
- **PII Detection** — Powered by Microsoft Presidio
- **Prompt Injection Prevention** — Multi-layer detection
- **Policy Engine** — GDPR, HIPAA, PCI-DSS templates
- **Immutable Audit Trail** — SHA-256 integrity hashing
- **Real-time Monitoring** — Usage, cost, security incidents

### Quick Start
```bash
# 1. Register and get your API key
POST /v1/auth/register  →  POST /v1/auth/token  →  POST /v1/auth/api-keys

# 2. Use as a drop-in for OpenAI
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="gvn_your_key_here"
)
```
    """,
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ── Middleware ─────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time", "X-Powered-By"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach a unique request ID to every request."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    start = time.monotonic()

    response = await call_next(request)

    duration_ms = (time.monotonic() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
    response.headers["X-Powered-By"] = "AI-Governance-Layer/1.0"

    return response


# ── Global Exception Handler ───────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "internal_server_error",
            "detail": str(exc) if settings.debug else "An unexpected error occurred",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# ── Health Check ───────────────────────────────────────────────
@app.get("/health", tags=["System"], summary="Health check")
async def health_check():
    """Returns service health status."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }


@app.get("/", tags=["System"], summary="API info")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "proxy_endpoint": "/v1/chat/completions",
    }


# ── Register Routers ───────────────────────────────────────────
from api.v1 import auth, proxy, policies, audit  # noqa: E402
from api.v1 import settings as settings_router  # noqa: E402

app.include_router(proxy.router)
app.include_router(auth.router)
app.include_router(policies.router)
app.include_router(audit.router)
app.include_router(settings_router.router)


# ── Admin Seed ─────────────────────────────────────────────────
async def _seed_admin():
    """Create default admin user and org on first run."""
    from sqlalchemy import select
    from core.database import AsyncSessionLocal
    from core.security import hash_password
    from models.db.models import Organization, User

    async with AsyncSessionLocal() as db:
        # Create default org if not exists
        result_org = await db.execute(select(Organization).where(Organization.slug == "default"))
        org = result_org.scalar_one_or_none()
        if not org:
            org = Organization(name="Default Organization", slug="default")
            db.add(org)
            await db.flush()

        # Check if admin exists
        result = await db.execute(select(User).where(User.email == settings.admin_email))
        if not result.scalar_one_or_none():
            safe_password = settings.admin_password[:72]
            admin = User(
                org_id=org.id,
                email=settings.admin_email,
                hashed_password=hash_password(safe_password),
                full_name="Admin",
                role="admin",
            )
            db.add(admin)
            await db.commit()
            logger.info("Default admin user created", email=settings.admin_email)

        # Ensure default dev key exists
        from models.db.models import ApiKey
        from core.security import _hash_api_key
        key_result = await db.execute(select(ApiKey).where(ApiKey.name == "Default Dev Key"))
        if not key_result.scalar_one_or_none():
            dev_key = "gvn_trainvector_live_key"
            api_key = ApiKey(
                org_id=org.id,
                name="Default Dev Key",
                key_prefix=dev_key[:12],
                key_hash=_hash_api_key(dev_key),
                permissions=["*"],
                is_active=True,
            )
            db.add(api_key)
            await db.commit()
            logger.info("Default development API key created", key="gvn_trainvector_live_key")


# ── Dev Server ─────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,  # AgenticAI backend runs on 8000, governance API on 8001
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
