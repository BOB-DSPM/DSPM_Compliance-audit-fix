# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, audit
import os

app = FastAPI(title="Compliance Mapping Auditor API", version="0.1.0")

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8103",
    "http://127.0.0.1:8103",
]
extra = os.getenv("CORS_ALLOW_ORIGINS", "")
if extra.strip():
    DEFAULT_ORIGINS += [o.strip() for o in extra.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # credentials=False이므로 * 가능
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(audit.router,  prefix="/audit",  tags=["audit"])
