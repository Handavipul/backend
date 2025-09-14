from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.orm import Session
import uvicorn
import ssl
from prometheus_fastapi_instrumentator import Instrumentator

from backend.config import settings
from backend.database import get_db, create_tables
from backend.routers import auth, mollie, otp, payment, compliance
from backend.services.aws_service import AWSService
from backend.middleware.metrics import MetricsMiddleware
from backend.middleware.security import SecurityMiddleware

app = FastAPI(
    title="Face Recognition Payment Gateway",
    version="2.0.0",
    description="Enterprise-grade biometric payment gateway with multi-angle face recognition",
    docs_url="/docs",
    redoc_url="/redoc",        # ReDoc UI
    openapi_url="/openapi.json"
)

# Security middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Metrics middleware
if settings.METRICS_ENABLED:
    app.add_middleware(MetricsMiddleware)
    instrumentator = Instrumentator()
    instrumentator.instrument(app)
    instrumentator.expose(app, endpoint=settings.METRICS_PATH)

# Security
security = HTTPBearer()

# Initialize services
aws_service = AWSService()

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["authentication"])
app.include_router(payment.router, prefix="/payment", tags=["payment"])
app.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
app.include_router(otp.router, prefix="/otp", tags=["otp"])
app.include_router(mollie.router, prefix="/mollie", tags=["mollie"])



@app.on_event("startup")
async def startup_event():
    create_tables()
    print("✅ Database tables created")
    print("✅ Face Recognition Payment Gateway started")
    if settings.MTLS_ENABLED:
        print("✅ mTLS enabled")
    if settings.METRICS_ENABLED:
        print(f"✅ Metrics exposed at {settings.METRICS_PATH}")

@app.get("/")
async def root():
    return {
        "message": "Face Recognition Payment Gateway API v2.0",
        "features": [
            "Multi-angle face capture",
            "JWT-based authorization",
            "mTLS-ready architecture",
            "Prometheus metrics",
            "Cloud-native design"
        ]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "payment-gateway",
        "version": "2.0.0",
        "timestamp": "2025-06-20T00:00:00Z"
    }

def create_ssl_context():
    """Create SSL context for mTLS"""
    if not settings.MTLS_ENABLED:
        return None
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    
    if settings.CA_CERT_PATH:
        context.load_verify_locations(settings.CA_CERT_PATH)
    if settings.CLIENT_CERT_PATH and settings.CLIENT_KEY_PATH:
        context.load_cert_chain(settings.CLIENT_CERT_PATH, settings.CLIENT_KEY_PATH)
    
    return context

if __name__ == "__main__":
    ssl_context = create_ssl_context()
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        ssl_keyfile=settings.CLIENT_KEY_PATH if settings.MTLS_ENABLED else None,
        ssl_certfile=settings.CLIENT_CERT_PATH if settings.MTLS_ENABLED else None,
        ssl_ca_certs=settings.CA_CERT_PATH if settings.MTLS_ENABLED else None,
        ssl_cert_reqs=ssl.CERT_REQUIRED if settings.MTLS_ENABLED else None
    )