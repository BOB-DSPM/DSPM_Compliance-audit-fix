# app/routers/audit.py
from __future__ import annotations

from fastapi import APIRouter, Path, Query
from fastapi.responses import StreamingResponse
import json
from app.services.audit_service import AuditService

router = APIRouter()

@router.post("/{framework}/_all", summary="(프레임워크) 전체 감사 수행")
def audit_framework(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    stream: bool = Query(False, description="True면 NDJSON으로 항목별 스트리밍 전송"),
):
    """
    stream=false(기본): 기존처럼 전체 결과를 한 번에 JSON으로 반환
    stream=true: application/x-ndjson 으로 RequirementAuditResponse를 요구사항별로 1줄씩 스트리밍
    """
    framework = framework.strip()
    svc = AuditService()

    if not stream:
        # 기존 동작 (배치 응답)
        return svc.audit_compliance(framework)

    # 스트리밍 동작 (NDJSON)
    def gen_ndjson():
        # 전체 요구사항 목록을 가져와 항목별로 감사 실행
        reqs = svc.mapping_client.get_requirements(framework)
        total = len(reqs)
        yield json.dumps({"type": "meta", "framework": framework, "total": total}, ensure_ascii=False) + "\n"

        executed = 0
        for r in reqs:
            res = svc.audit_requirement(framework, r.id)
            executed += 1
            # 각 요구사항 결과를 한 줄 NDJSON으로 전송
            yield json.dumps(
                {
                    "type": "requirement",
                    "framework": res.framework,
                    "requirement_id": res.requirement_id,
                    "item_code": res.item_code,
                    "requirement_status": res.requirement_status,
                    "summary": res.summary,
                    "results": [r.dict() for r in res.results],  # 세부 매핑 결과 포함
                },
                ensure_ascii=False,
            ) + "\n"

        # 마지막에 집계 요약 라인 전송(프론트에서 진행률/요약 표시 용이)
        yield json.dumps({"type": "summary", "framework": framework, "executed": executed, "total": total}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen_ndjson(), media_type="application/x-ndjson; charset=utf-8")


@router.post("/{framework}/{req_id:int}", summary="(항목) 감사 수행")
def audit_requirement(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    req_id: int = Path(..., description="매핑 백엔드의 requirement.id"),
):
    framework = framework.strip()
    svc = AuditService()
    return svc.audit_requirement(framework, req_id)
