# app/routers/audit.py
from __future__ import annotations

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import StreamingResponse
import json

from app.services.audit_service import AuditService
from app.core.config import settings
from app.core.session import ensure_session, use_session

# ⬇ 세션 TTL 캐시 + ETag 유틸 (이미 추가해둔 유틸을 사용)
from app.utils.caching import maybe_return_cached, store_response_to_cache
from app.utils.etag_utils import etag_response
from app.utils.session_introspect import peek_session as _peek_session, list_sessions as _list_sessions

router = APIRouter()

@router.get("/session", summary="세션 목록 또는 단건 조회(쿼리)")
def session_overview(session_id: str | None = Query(None, description="조회할 세션 ID(없으면 전체 요약)")):
    """
    - session_id가 주어지면: 해당 세션 존재 여부와 요약 정보 반환
    - 없으면: 모든 세션의 요약 목록 반환
    """
    if session_id:
        return _peek_session(session_id)
    return _list_sessions()


@router.get("/session/{session_id}", summary="세션 단건 조회(존재 확인)")
def session_get(session_id: str = Path(..., description="세션 ID")):
    """
    특정 세션 존재 여부와 요약 정보를 반환.
    """
    return _peek_session(session_id)

@router.post("/{framework}/_all", summary="(프레임워크) 전체 감사 수행")
async def audit_framework(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    stream: bool = Query(False, description="True면 NDJSON으로 항목별 스트리밍 전송"),
    session_id: str | None = Query(None, description="세션 ID(있으면 boto3/httpx 재사용)"),
    session_ttl: int = Query(600, ge=0, description="세션 TTL(초). 0이면 만료 관리 안함"),
    request: Request = None,
    response: Response = None,
):
    """
    - stream=False: JSON 한 방 응답 → 캐시/ETag 적용
    - stream=True : NDJSON 스트리밍 → 캐시/ETag 미적용
    """
    framework = framework.strip()
    svc = AuditService()

    # ─────────────────────────────────────────────────────
    # 비스트리밍 모드: 캐시/ETag 경로 (세션 유무와 무관)
    # ─────────────────────────────────────────────────────
    if not stream:
        # 1) 캐시 조회 (?refresh=1 이면 BYPASS)
        cached = await maybe_return_cached(request, response, ttl=600)
        if cached is not None:
            return etag_response(request, response, cached)

        # 2) 실제 실행
        if not session_id:
            result = svc.audit_compliance(framework)
        else:
            s = ensure_session(session_id, region=settings.AWS_REGION, profile=None, ttl_seconds=session_ttl)
            with use_session(s):
                result = svc.audit_compliance(framework)

        # 3) 캐시에 저장 + ETag/Cache-Control
        store_response_to_cache(request, result)
        response.headers["Cache-Control"] = "public, max-age=600"
        return etag_response(request, response, result)

    # ─────────────────────────────────────────────────────
    # 스트리밍 모드: 기존 NDJSON 흐름 유지 (캐시/ETag 제외)
    # ─────────────────────────────────────────────────────
    if not session_id:
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

    # 세션 모드 스트리밍
    s = ensure_session(session_id, region=settings.AWS_REGION, profile=None, ttl_seconds=session_ttl)

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
async def audit_requirement(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    req_id: int = Path(..., description="매핑 백엔드의 requirement.id"),
    session_id: str | None = Query(None, description="세션 ID(있으면 boto3/httpx 재사용)"),
    session_ttl: int = Query(600, ge=0, description="세션 TTL(초). 0이면 만료 관리 안함"),
    request: Request = None,
    response: Response = None,
):
    """
    단일 항목 감사는 항상 한 방 JSON 응답 → 캐시/ETag 적용
    """
    framework = framework.strip()
    svc = AuditService()

    # 1) 캐시 조회
    cached = await maybe_return_cached(request, response, ttl=600)
    if cached is not None:
        return etag_response(request, response, cached)

    # 2) 실제 실행
    if not session_id:
        result = svc.audit_requirement(framework, req_id)
    else:
        s = ensure_session(session_id, region=settings.AWS_REGION, profile=None, ttl_seconds=session_ttl)
        with use_session(s):
            result = svc.audit_requirement(framework, req_id)

    # 3) 캐시에 저장 + ETag/Cache-Control
    store_response_to_cache(request, result)
    response.headers["Cache-Control"] = "public, max-age=600"
    return etag_response(request, response, result)
