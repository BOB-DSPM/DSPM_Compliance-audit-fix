# app/main.py
from fastapi import FastAPI
from app.routers import health, audit

app = FastAPI(title="Compliance Mapping Auditor API", version="0.1.0")

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(audit.router, prefix="/audit", tags=["audit"])

