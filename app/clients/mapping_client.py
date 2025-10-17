# app/clients/mapping_client.py
from __future__ import annotations

import httpx
from urllib.parse import quote
from typing import List

from app.core.config import settings
from app.models.schemas import RequirementRowOut, RequirementDetailOut
from app.core.session import CURRENT_HTTPX_CLIENT

class MappingClient:
    """
    Compliance Mapping API 호출 클라이언트
    세션 컨텍스트에 httpx.Client가 있으면 재사용
    """
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.MAPPING_BASE_URL).rstrip("/")

    def _http(self) -> httpx.Client:
        cli = CURRENT_HTTPX_CLIENT.get()
        return cli if cli is not None else httpx.Client(timeout=30.0)

    def _safe_code(self, framework: str) -> str:
        return quote(framework.strip(), safe="")

    def get_requirements(self, framework: str) -> List[RequirementRowOut]:
        code = self._safe_code(framework)
        url = f"{self.base_url}/compliance/{code}/requirements"
        h = self._http()
        close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(url, timeout=30.0)
            r.raise_for_status()
            data = r.json()
            return [RequirementRowOut(**x) for x in data]
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def get_requirement_mappings(self, framework: str, req_id: int) -> RequirementDetailOut:
        code = self._safe_code(framework)
        url = f"{self.base_url}/compliance/{code}/requirements/{req_id}/mappings"
        h = self._http()
        close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(url, timeout=30.0)
            r.raise_for_status()
            return RequirementDetailOut(**r.json())
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass
