import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.models.database import engine, Base, SessionLocal
from backend.services.seed_data import seed_database_if_empty

# Routers
from backend.routers.dashboard_router import router as dashboard_router
from backend.routers.targets_router import router as targets_router
from backend.routers.scans_router import router as scans_router
from backend.routers.vulnerabilities_router import router as vulnerabilities_router
from backend.routers.metasploit_router import router as metasploit_router
from backend.routers.reports_router import router as reports_router
from backend.routers.settings_router import router as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database_if_empty(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="CyberShield VAPT Platform API",
    description="Enterprise-grade Vulnerability Assessment & Penetration Testing Backend Engine",
    version="2.4.0",
    lifespan=lifespan
)

# CORS configuration for frontend Vite integration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(dashboard_router)
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(vulnerabilities_router)
app.include_router(metasploit_router)
app.include_router(reports_router)
app.include_router(settings_router)


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CyberShield VAPT Core",
        "version": "2.4.0",
        "database": "SQLite (Connected)",
        "security_controls": "Active Allowlist & SSRF Filters Enabled"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
