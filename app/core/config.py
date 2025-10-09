# app/core/config.py
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl

class Settings(BaseSettings):
    # ---- 외부 서비스 베이스 URL ----
    # 매핑 백엔드 (Compliance Mapping API: localhost:8003)
    MAPPING_BASE_URL: AnyHttpUrl | str = "http://localhost:8003"
    # 리소스 수집기 (AWS Resource Collector API: localhost:8000)
    COLLECTOR_BASE_URL: AnyHttpUrl | str = "http://localhost:8000"

    # ---- AWS 공통 ----
    AWS_REGION: str = "ap-northeast-2"  # 필요 시 변경

    # ---- pydantic-settings 구성 ----
    model_config = SettingsConfigDict(
        env_file=".env",     # .env에서 환경변수 로드
        env_file_encoding="utf-8",
        extra="ignore"       # 정의되지 않은 env가 있어도 무시
    )

# 전역 싱글톤
settings = Settings()
