# app/routers/audit.py
from __future__ import annotations

from fastapi import APIRouter, Path, Query
from fastapi.responses import StreamingResponse
import json

from app.services.audit_service import AuditService
from app.core.config import settings
from app.core.session import ensure_session, use_session

router = APIRouter()

@router.post("/{framework}/_all", summary="(프레임워크) 전체 감사 수행")
def audit_framework(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    stream: bool = Query(False, description="True면 NDJSON으로 항목별 스트리밍 전송"),
    session_id: str | None = Query(None, description="세션 ID(있으면 boto3/httpx 재사용)"),
    session_ttl: int = Query(600, ge=0, description="세션 TTL(초). 0이면 만료 관리 안함"),
):
    framework = framework.strip()
    svc = AuditService()

    if not session_id:
        # 기존 동작
        if not stream:
            return svc.audit_compliance(framework)

        def gen_ndjson_no_session():
            reqs = svc.mapping_client.get_requirements(framework)
            total = len(reqs)
            yield json.dumps({"type": "meta", "framework": framework, "total": total}, ensure_ascii=False) + "\n"
            executed = 0
            for r in reqs:
                res = svc.audit_requirement(framework, r.id)
                executed += 1
                yield json.dumps(
                    {
                        "type": "requirement",
                        "framework": res.framework,
                        "requirement_id": res.requirement_id,
                        "item_code": res.item_code,
                        "requirement_status": res.requirement_status,
                        "summary": res.summary,
                        "results": [rr.dict() for rr in res.results],
                    },
                    ensure_ascii=False,
                ) + "\n"
            yield json.dumps({"type": "summary", "framework": framework, "executed": executed, "total": total}, ensure_ascii=False) + "\n"

        return StreamingResponse(gen_ndjson_no_session(), media_type="application/x-ndjson; charset=utf-8")

    # 세션 모드
    s = ensure_session(session_id, region=settings.AWS_REGION, profile=None, ttl_seconds=session_ttl)

    if not stream:
        with use_session(s):
            return svc.audit_compliance(framework)

    def gen_ndjson_with_session():
        with use_session(s):
            reqs = svc.mapping_client.get_requirements(framework)
            total = len(reqs)
            yield json.dumps({"type": "meta", "framework": framework, "total": total}, ensure_ascii=False) + "\n"
            executed = 0
            for r in reqs:
                res = svc.audit_requirement(framework, r.id)
                executed += 1
                yield json.dumps(
                    {
                        "type": "requirement",
                        "framework": res.framework,
                        "requirement_id": res.requirement_id,
                        "item_code": res.item_code,
                        "requirement_status": res.requirement_status,
                        "summary": res.summary,
                        "results": [rr.dict() for rr in res.results],
                    },
                    ensure_ascii=False,
                ) + "\n"
            yield json.dumps({"type": "summary", "framework": framework, "executed": executed, "total": total}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen_ndjson_with_session(), media_type="application/x-ndjson; charset=utf-8")


@router.post("/audit/{framework}/{req_id:int}", summary="(항목) 감사 수행")
def audit_requirement(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    req_id: int = Path(..., description="매핑 백엔드의 requirement.id"),
    session_id: str | None = Query(None, description="세션 ID(있으면 boto3/httpx 재사용)"),
    session_ttl: int = Query(600, ge=0, description="세션 TTL(초). 0이면 만료 관리 안함"),
):
    framework = framework.strip()
    svc = AuditService()

    if not session_id:
        return svc.audit_requirement(framework, req_id)

    s = ensure_session(session_id, region=settings.AWS_REGION, profile=None, ttl_seconds=session_ttl)
    with use_session(s):
        return svc.audit_requirement(framework, req_id)
