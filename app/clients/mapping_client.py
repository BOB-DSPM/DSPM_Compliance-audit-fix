from __future__ import annotations

import httpx
from urllib.parse import quote
from typing import List

from app.core.config import settings
from app.models.schemas import RequirementRowOut, RequirementDetailOut


class MappingClient:
    """
    Compliance Mapping API (예: localhost:8003) 호출 클라이언트
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.MAPPING_BASE_URL).rstrip("/")

    def _safe_code(self, framework: str) -> str:
        """
        프레임워크 코드를 path 세그먼트에 안전하게 넣기 위해:
        - strip()으로 양끝 공백 제거
        - quote()로 URL 인코딩
        """
        return quote(framework.strip(), safe="")

    def get_requirements(self, framework: str) -> List[RequirementRowOut]:
        """
        GET /compliance/{code}/requirements
        """
        code = self._safe_code(framework)
        url = f"{self.base_url}/compliance/{code}/requirements"
        r = httpx.get(url, timeout=30.0)
        r.raise_for_status()
        data = r.json()
        return [RequirementRowOut(**x) for x in data]

    def get_requirement_mappings(self, framework: str, req_id: int) -> RequirementDetailOut:
        """
        GET /compliance/{code}/requirements/{req_id}/mappings
        """
        code = self._safe_code(framework)
        url = f"{self.base_url}/compliance/{code}/requirements/{req_id}/mappings"
        r = httpx.get(url, timeout=30.0)
        r.raise_for_status()
        return RequirementDetailOut(**r.json())
