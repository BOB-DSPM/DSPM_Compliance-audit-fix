# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8103 \
    APP_HOME=/app

# 기본 유틸만 설치 (tzdata는 로그 타임스탬프 때문에 포함)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR ${APP_HOME}

# 1) 의존성만 먼저 복사/설치해서 Docker 레이어 캐시 활용
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# 2) 앱 소스만 복사 (불필요한 루트 파일/폴더는 .dockerignore로 제외)
COPY app ./app

# 비루트 유저 사용 (권장)
RUN useradd --create-home --shell /bin/bash appuser \
 && chown -R appuser:appuser ${APP_HOME}
USER appuser

EXPOSE 8103
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

# FastAPI 실행
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8103"]
