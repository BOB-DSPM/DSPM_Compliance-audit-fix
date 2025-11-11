# app/routers/audit.py
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Generator, Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse

from app.core.session import get_or_create_session, use_session
from app.services.audit_service import AuditService
from app.utils.session_introspect import peek_session
from app.utils.session_mark import mark_session_framework

router = APIRouter()

AUDIT = AuditService()

def _normalize_session_id(raw: Optional[str]) -> str:
  if not raw:
    return str(uuid.uuid4())
  try:
    return str(uuid.UUID(str(raw)))
  except Exception:
    return str(uuid.uuid4())

@router.get("/session/{session_id}")
def get_session(session_id: str):
  """
  프론트 확인용 세션 조회 엔드포인트 (complianceApi.checkSession에서 사용)
  """
  info = peek_session(session_id)
  if not info.get("exists"):
    return JSONResponse({"exists": False}, status_code=404)
  return JSONResponse(info)

@router.post("/{framework}/_all")
async def audit_all(framework: str, request: Request):
  """
  프레임워크 전체 감사.
  - query: stream=true -> NDJSON 스트리밍
  - query: stream=false(default) -> 일괄 JSON
  - query: session_id=<uuid>
  """
  qp = dict(request.query_params)
  stream = str(qp.get("stream", "false")).lower() == "true"
  raw_sid = qp.get("session_id")
  sid = _normalize_session_id(raw_sid)
  session = get_or_create_session(sid)
  mark_session_framework(session, framework)

  if not stream:
    # 배치 모드(일괄 JSON)
    with use_session(session):
      data = AUDIT.audit_compliance(framework)
    return JSONResponse(data)

  # 스트리밍(NDJSON) 모드
  def gen_ndjson_with_session() -> Generator[bytes, None, None]:
    # 메타(총 개수) 먼저 송신
    with use_session(session):
      # 각 요구사항을 순차 처리하는 로직을 AuditService 내부에서 재사용
      batch = AUDIT.audit_compliance(framework)
    total = int(batch.get("total_requirements", 0))
    yield (json.dumps({"type": "meta", "framework": framework, "total": total}, ensure_ascii=False) + "\n").encode("utf-8")

    # 다시 세션 컨텍스트에서 각 결과를 흘려보냄
    with use_session(session):
      for item in batch.get("results", []):
        req_id = item.get("requirement_id")
        status = item.get("requirement_status")
        evt = {"type": "requirement", "framework": framework, "requirement_id": req_id, "requirement_status": status, **item}
        yield (json.dumps(evt, ensure_ascii=False) + "\n").encode("utf-8")

      # 요약 (선택)
      summary_evt = {"type": "summary", "framework": framework}
      yield (json.dumps(summary_evt, ensure_ascii=False) + "\n").encode("utf-8")

  headers = {"Content-Type": "application/x-ndjson; charset=utf-8"}
  return StreamingResponse(gen_ndjson_with_session(), headers=headers)

@router.post("/audit/{framework}/{req_id}")
async def audit_one(framework: str, req_id: int, request: Request):
  """
  특정 요구사항 감사 (JSON)
  - query: session_id=<uuid>
  """
  raw_sid = request.query_params.get("session_id")
  sid = _normalize_session_id(raw_sid)
  session = get_or_create_session(sid)
  mark_session_framework(session, framework)

  with use_session(session):
    result = AUDIT.audit_requirement(framework, int(req_id))
  return JSONResponse(result.dict())
