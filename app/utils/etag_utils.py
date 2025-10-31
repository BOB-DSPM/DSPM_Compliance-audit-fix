# app/utils/etag_utils.py
from __future__ import annotations

import dataclasses
import datetime as dt
import decimal
import hashlib
import json
from typing import Any

from pydantic import BaseModel
from starlette.responses import JSONResponse, Response


def _to_jsonable(obj: Any) -> Any:
    """
    Pydantic BaseModel, dataclass, datetime/Decimal, list/tuple/dict를
    JSON 직렬화 가능한 값들로 변환.
    """
    if isinstance(obj, BaseModel):
        # alias 적용 + None 필드 제외 (해시 안정성 ↑)
        return obj.model_dump(by_alias=True, exclude_none=True)
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (dt.datetime, dt.date, dt.time)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        # 소수는 부동으로 변환 (정책에 맞게 필요 시 str(obj)로 교체)
        return float(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    return obj


def _stable_bytes(data: Any) -> bytes:
    """
    정렬된 키/안정적 구분자를 사용해 항상 동일 바이트 시퀀스를 생성.
    """
    coerced = _to_jsonable(data)
    return json.dumps(
        coerced,
        ensure_ascii=False,
        separators=(",", ":"),   # 공백 제거 → 바이트 안정성
        sort_keys=True,          # 키 정렬 → 바이트 안정성
    ).encode("utf-8")


def _etag_for(data: Any) -> str:
    return hashlib.sha256(_stable_bytes(data)).hexdigest()


def etag_response(
    request,
    response: Response | None,
    data: Any,
    status_code: int = 200,
) -> Response:
    """
    ETag 인식 JSON 응답 생성.
    - BaseModel/dataclass/datetime/Decimal 등 안전 직렬화
    - If-None-Match 일치 시 304 반환
    - Cache-Control/ETag 헤더 설정
    """
    etag = _etag_for(data)
    inm = request.headers.get("if-none-match")
    if inm and inm.strip('"') == etag:
        r304 = Response(status_code=304)
        r304.headers["ETag"] = f'"{etag}"'
        r304.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return r304

    payload = _to_jsonable(data)
    r = JSONResponse(content=payload, status_code=status_code)
    r.headers["ETag"] = f'"{etag}"'
    r.headers["Cache-Control"] = "private, max-age=0, must-revalidate"

    # 호출자가 넘긴 response 객체가 있으면 동기화(선택적)
    if response is not None:
        response.headers["ETag"] = f'"{etag}"'
        response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"

    return r
