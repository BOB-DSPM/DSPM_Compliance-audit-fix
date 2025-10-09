import httpx
from typing import List
from app.core.config import settings
from app.models.show_schemas import RequirementRowOut, RequirementDetailOut

class MappingClient:
    def __init__(self, base_url: str = str(settings.MAPPING_API_BASE)):
        # ✅ 끝 슬래시 제거하여 // 방지
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=30.0)

    def get_requirements(self, framework_code: str) -> List[RequirementRowOut]:
        url = f"{self.base_url}/compliance/compliance/{framework_code}/requirements"
        r = self._client.get(url)
        r.raise_for_status()
        data = r.json()
        return [RequirementRowOut.model_validate(x) for x in data]

    def get_requirement_mappings(self, framework_code: str, req_id: int) -> RequirementDetailOut:
        url = f"{self.base_url}/compliance/compliance/{framework_code}/requirements/{req_id}/mappings"
        r = self._client.get(url)
        r.raise_for_status()
        return RequirementDetailOut.model_validate(r.json())
