from __future__ import annotations
import hashlib, json
from fastapi import Request, Response
from fastapi.responses import JSONResponse

def _hash_body(data) -> str:
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return '"' + hashlib.sha1(body).hexdigest() + '"'  # ETag 포맷: 쿼트 포함

def etag_response(request: Request, response: Response, data):
    etag = _hash_body(data)
    inm = request.headers.get("If-None-Match")
    response.headers["ETag"] = etag
    if inm == etag:
        response.status_code = 304
        return Response(status_code=304)
    return JSONResponse(content=data)
