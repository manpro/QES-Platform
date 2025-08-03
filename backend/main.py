"""
eIDAS QES Digital Signing Platform - Main FastAPI Application

This is the main entry point for the backend API service.
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import os
from datetime import datetime
from contextlib import asynccontextmanager

# Import routers (to be implemented)
# from .routers import auth, signing, admin, health

app_version = "1.0.0-dev"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("Starting eIDAS QES Platform...")
    # Initialize database, Vault connections, etc.
    yield
    # Shutdown
    print("Shutting down eIDAS QES Platform...")


# Create FastAPI app
app = FastAPI(
    title="eIDAS QES Digital Signing Platform",
    description="""
    A production-grade digital-signature service that complies with 
    eIDAS Qualified Electronic Signature (QES) standards.
    
    Features:
    - Multi-tenant SaaS and on-premise deployment
    - Pluggable QES providers per country
    - XAdES-LTA & PAdES-LTA compliance
    - Audit logging and observability
    """,
    version=app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3003",
        "http://localhost:3000", 
        "http://127.0.0.1:3003",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "eIDAS QES Digital Signing Platform",
        "version": app_version,
        "status": "operational",
        "docs": "/api/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Comprehensive health checks
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": app_version,
        "checks": {}
    }
    
    # Database health check
    try:
        from database import engine
        from sqlalchemy import text
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        health_status["checks"]["database"] = {
            "status": "healthy",
            "type": "postgresql"
        }
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "type": "postgresql"
        }
        health_status["status"] = "degraded"
    
    # Redis health check
    try:
        import redis
        import os
        redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6380"))
        redis_client.ping()
        health_status["checks"]["redis"] = {
            "status": "healthy",
            "type": "redis"
        }
        redis_client.close()
    except Exception as e:
        health_status["checks"]["redis"] = {
            "status": "unhealthy", 
            "error": str(e),
            "type": "redis"
        }
        health_status["status"] = "degraded"
    
    # MinIO health check
    try:
        from storage.minio_client import get_minio_client
        minio_client = get_minio_client()
        # Simple connectivity test
        list(minio_client.list_buckets())
        health_status["checks"]["minio"] = {
            "status": "healthy",
            "type": "object_storage"
        }
    except Exception as e:
        health_status["checks"]["minio"] = {
            "status": "unhealthy",
            "error": str(e),
            "type": "object_storage"
        }
        health_status["status"] = "degraded"
    
    # Vault health check
    try:
        import hvac
        vault_client = hvac.Client(url=os.getenv("VAULT_ADDR", "http://localhost:8202"))
        if vault_client.sys.is_initialized() and vault_client.sys.is_sealed() is False:
            health_status["checks"]["vault"] = {
                "status": "healthy",
                "type": "secrets_manager"
            }
        else:
            health_status["checks"]["vault"] = {
                "status": "degraded",
                "reason": "sealed_or_uninitialized",
                "type": "secrets_manager"
            }
    except Exception as e:
        health_status["checks"]["vault"] = {
            "status": "unhealthy",
            "error": str(e),
            "type": "secrets_manager"
        }
        health_status["status"] = "degraded"
    
    # Overall status determination
    unhealthy_checks = [check for check in health_status["checks"].values() 
                       if check["status"] == "unhealthy"]
    
    if unhealthy_checks:
        health_status["status"] = "unhealthy"
        raise HTTPException(status_code=503, detail=health_status)
    elif any(check["status"] == "degraded" for check in health_status["checks"].values()):
        health_status["status"] = "degraded"
    
    return health_status


# Include routers
from api import documents, signatures, audit, document_verification, tsa, tsa_advanced, performance, biometric, blockchain, billing, usage, metrics, eu_dss_api
from auth.routes import router as auth_router
# Include API routes
app.include_router(auth_router, prefix="/auth")
app.include_router(documents.router, prefix="/api/v1/documents")
app.include_router(signatures.router, prefix="/api/v1/signatures")
app.include_router(audit.router, prefix="/api/v1/audit")
app.include_router(document_verification.router, prefix="/api/v1/document-verification")
app.include_router(tsa.router, prefix="/api/v1/tsa")
app.include_router(tsa_advanced.router, prefix="/api/v1/tsa-advanced")
app.include_router(eu_dss_api.router, prefix="/api/v1/eu-dss")
app.include_router(performance.router, prefix="/api/v1/performance")
app.include_router(biometric.router, prefix="/api/v1/biometric")
app.include_router(blockchain.router, prefix="/api/v1/blockchain")
app.include_router(billing.router, prefix="/api/v1/billing")
app.include_router(usage.router, prefix="/api/v1/usage")
app.include_router(metrics.router, prefix="/api/v1/metrics")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )