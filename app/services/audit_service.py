# app/services/audit_service.py
from __future__ import annotations
from typing import List, Dict, Any
from app.clients.mapping_client import MappingClient
from app.services.registry import make_executor
from app.models.schemas import AuditResult, RequirementAuditResponse, Status

def _summarize_status(results: List[AuditResult]) -> Dict[str, int]:
    summary = {"COMPLIANT": 0, "NON_COMPLIANT": 0, "SKIPPED": 0, "ERROR": 0}
    for r in results:
        summary[r.status] = summary.get(r.status, 0) + 1
    return summary

def _decide_overall_status(summary: Dict[str, int]) -> Status:
    # 우선순위: ERROR > NON_COMPLIANT > COMPLIANT > SKIPPED
    if summary.get("ERROR", 0) > 0:
        return "ERROR"
    if summary.get("NON_COMPLIANT", 0) > 0:
        return "NON_COMPLIANT"
    if summary.get("COMPLIANT", 0) > 0:
        return "COMPLIANT"
    return "SKIPPED"

class AuditService:
    def __init__(self, mapping_client: MappingClient | None = None):
        self.mapping_client = mapping_client or MappingClient()

    def audit_requirement(self, framework: str, req_id: int) -> RequirementAuditResponse:
        detail = self.mapping_client.get_requirement_mappings(framework, req_id)
        req = detail.requirement
        results: List[AuditResult] = []

        for m in detail.mappings:
            executor = make_executor(m.code)
            if executor:
                results.append(executor.audit())
            else:
                results.append(
                    AuditResult(
                        mapping_code=m.code,
                        status="SKIPPED",
                        reason="미구현 매핑",
                        evaluations=[],
                        evidence={},
                    )
                )

        summary = _summarize_status(results)
        requirement_status = _decide_overall_status(summary)

        return RequirementAuditResponse(
            framework=framework,
            requirement_id=req.id,
            item_code=req.item_code or req.title,
            results=results,
            requirement_status=requirement_status,
            summary=summary,
        )

    def audit_compliance(self, framework: str) -> Dict[str, Any]:
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
