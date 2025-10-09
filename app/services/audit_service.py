# app/services/audit_service.py
from typing import List, Dict, Any
from app.clients.mapping_client import MappingClient
from app.services.registry import make_executor
from app.models.schemas import (
    AuditResult,
    RequirementAuditResponse,
    MappingExtract,
)

class AuditService:
    def __init__(self, mapping_client: MappingClient | None = None):
        self.mapping_client = mapping_client or MappingClient()

    def audit_requirement(self, framework: str, req_id: int) -> RequirementAuditResponse:
        """
        단일 요구사항(req_id)에 매핑된 모든 매핑코드를 실행하고,
        각 결과에 제목(title)과 매핑 메타(extract)를 채워 반환.
        """
        detail = self.mapping_client.get_requirement_mappings(framework, req_id)
        req = detail.requirement
        results: List[AuditResult] = []

        for m in detail.mappings:
            code = m.code
            executor = make_executor(code)

            # 1) 매핑 코드 실행 (없으면 SKIPPED)
            if executor:
                result = executor.audit()
            else:
                result = AuditResult(
                    mapping_code=code,
                    status="SKIPPED",
                    reason="미구현 매핑",
                    evidence={},
                    evaluations=[]
                )

            # 2) 제목/추출 메타 채우기
            # title 우선순위: 서비스명 > 카테고리 > 매핑코드
            result.title = m.service or m.category or m.code
            result.extract = MappingExtract(
                code=m.code,
                category=m.category,
                service=m.service,
                console_path=m.console_path,
                check_how=m.check_how,
                cli_cmd=m.cli_cmd,
                return_field=m.return_field,
                compliant_value=m.compliant_value,
                non_compliant_value=m.non_compliant_value,
                console_fix=m.console_fix,
                cli_fix_cmd=m.cli_fix_cmd,
            )

            results.append(result)

        return RequirementAuditResponse(
            framework=framework,
            requirement_id=req.id,
            item_code=req.item_code or req.title,
            results=results
        )

    def audit_compliance(self, framework: str) -> Dict[str, Any]:
        """
        프레임워크 내 모든 요구사항을 순회 감사.
        각 요구사항의 상세 응답을 수집하고, 최상단 요약(summary) 카운트까지 포함해 반환.
        """
        reqs = self.mapping_client.get_requirements(framework)
        out: Dict[str, Any] = {
            "framework": framework,
            "total_requirements": len(reqs),
            "executed": 0,
            "results": []
        }

        # 상태 요약(매핑 레벨)
        summary = {"COMPLIANT": 0, "NON_COMPLIANT": 0, "SKIPPED": 0, "ERROR": 0}

        for r in reqs:
            res = self.audit_requirement(framework, r.id)

            # Pydantic v2: dict() 대신 model_dump()
            out["results"].append(res.model_dump())
            out["executed"] += 1

            # 요약 카운트 집계 (각 요구사항의 매핑 결과 상태)
            for mres in res.results:
                summary[mres.status] = summary.get(mres.status, 0) + 1

        out["summary"] = summary
        return out
