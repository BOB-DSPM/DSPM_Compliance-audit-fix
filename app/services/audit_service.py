from __future__ import annotations

from typing import List, Dict, Any

from app.clients.mapping_client import MappingClient
from app.services.registry import make_executor
from app.models.schemas import AuditResult, RequirementAuditResponse


class AuditService:
    def __init__(self, mapping_client: MappingClient | None = None):
        self.mapping_client = mapping_client or MappingClient()

    def audit_requirement(self, framework: str, req_id: int) -> RequirementAuditResponse:
        """
        단일 요구사항(req_id)의 매핑 리스트를 조회하여,
        매핑코드 별 실행기(executor)를 통해 감사를 수행한다.
        """
        framework = framework.strip()  # 방어 코드
        detail = self.mapping_client.get_requirement_mappings(framework, req_id)
        req = detail.requirement

        results: List[AuditResult] = []
        for m in detail.mappings:
            code = m.code
            executor = make_executor(code)
            if executor:
                results.append(executor.audit())
            else:
                # 미구현 매핑은 SKIPPED 처리
                results.append(
                    AuditResult(
                        mapping_code=code,
                        status="SKIPPED",
                        reason="미구현 매핑",
                        evidence={},
                    )
                )

        return RequirementAuditResponse(
            framework=framework,
            requirement_id=req.id,
            item_code=req.item_code or req.title,
            results=results,
        )

    def audit_compliance(self, framework: str) -> Dict[str, Any]:
        """
        프레임워크의 모든 요구사항을 순회하며 감사.
        """
        framework = framework.strip()  # 방어 코드
        reqs = self.mapping_client.get_requirements(framework)

        out: Dict[str, Any] = {
            "framework": framework,
            "total_requirements": len(reqs),
            "executed": 0,
            "results": [],
        }

        for r in reqs:
            res = self.audit_requirement(framework, r.id)
            out["results"].append(res.dict())
            out["executed"] += 1

        return out
