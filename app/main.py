# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, audit
import os

app = FastAPI(title="Compliance Mapping Auditor API", version="0.1.0")

# ── CORS 설정 ────────────────────────────────────────────────────────────────
# 개발 기본(Next/Vite dev) + Swagger 로컬 확인
DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8103",     # 이 API의 Swagger를 브라우저로 열 때
    "http://127.0.0.1:8103",
]

# 배포/개발 환경에서 추가로 허용할 오리진을 쉼표로 주입 가능:
#   CORS_ALLOW_ORIGINS="https://admin.example.com,https://app.example.com"
extra = os.getenv("CORS_ALLOW_ORIGINS", "")
if extra.strip():
    DEFAULT_ORIGINS += [o.strip() for o in extra.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # credentials=True면 "*" 금지. 정확히 나열
    allow_credentials=False,          # 쿠키/세션/인증 포함 요청 지원
    allow_methods=["*"],             # 필요시 ["GET","POST","PUT","DELETE","OPTIONS"]
    allow_headers=["*"],             # Authorization, Content-Type 등
    expose_headers=["ETag"],         # 프론트에서 읽어야 하는 응답 헤더 있으면 추가
    max_age=86400,                   # 프리플라이트 캐시(초)
)
# ────────────────────────────────────────────────────────────────────────────

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(audit.router,  prefix="/audit",  tags=["audit"])
