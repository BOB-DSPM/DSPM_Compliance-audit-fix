from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl
from typing import List


class Settings(BaseSettings):
    # ---- Gateway 경유 베이스 URL (프리픽스 포함) ----
    # 기존: http://localhost:8003  → 게이트웨이: http://211.44.183.248:9000/compliance
    MAPPING_BASE_URL: AnyHttpUrl | str = "http://211.44.183.248:9000/compliance"
    # 기존: http://localhost:8000  → 게이트웨이: http://211.44.183.248:9000/collector
    COLLECTOR_BASE_URL: AnyHttpUrl | str = "http://211.44.183.248:9000/collector"

    # (참고) 다른 서비스도 필요하면 이렇게 추가하면 됩니다:
    # AUDITOR_BASE_URL: AnyHttpUrl | str = "http://211.44.183.248:9000/auditor"
    # LINEAGE_BASE_URL: AnyHttpUrl | str = "http://211.44.183.248:9000/lineage"
    # AEGIS_BASE_URL:   AnyHttpUrl | str = "http://211.44.183.248:9000/aegis"

    # ---- AWS 공통 ----
    AWS_REGION: str = "ap-northeast-2"

    # ---- 감사 파라미터 (기본값) ----
    # 1.0-01: SSO Permission Set 최대 허용 개수 (조직 정책에 맞게 조정)
    SSO_PERMISSION_SET_MAX: int = 10

    # 1.0-02: 최소 1개 이상의 SCP가 존재해야 한다
    ORG_REQUIRE_SCP_MIN: int = 1

    # 2.0-15: CloudFront 허용 ViewerProtocolPolicy 집합
    CLOUDFRONT_ALLOWED_VIEWER_POLICIES: List[str] = [
        "redirect-to-https",
        "https-only",
    ]

    # 필요시 타임아웃/리트라이 등도 여기서 관리 가능
    HTTP_TIMEOUT_SECONDS: int = 30

    # ---- pydantic-settings 구성 ----
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
