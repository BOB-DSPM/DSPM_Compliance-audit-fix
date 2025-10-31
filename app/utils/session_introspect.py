# app/utils/session_introspect.py
from __future__ import annotations
from typing import Any, Dict, Optional, List
from datetime import datetime

def _to_iso(dt: Any) -> Optional[str]:
    try:
        if isinstance(dt, datetime):
            return dt.isoformat()
        # datetime-like (e.g. pendulum) 객체 호환
        return getattr(dt, "isoformat")()
    except Exception:
        return None

def _session_to_dict(sobj: Any) -> Dict[str, Any]:
    """
    세션 객체의 대표 필드들을 최대한 안전하게 추출.
    내부 구현에 따라 없는 필드는 생략.
    """
    out: Dict[str, Any] = {}
    for k in ("id", "session_id", "region", "profile", "ttl_seconds"):
        v = getattr(sobj, k, None)
        if v is not None:
            out[k if k != "session_id" else "id"] = v

    # 시간 필드 추정
    created = getattr(sobj, "created_at", None) or getattr(sobj, "created", None)
    last    = getattr(sobj, "last_used_at", None) or getattr(sobj, "last_used", None)
    exp     = getattr(sobj, "expires_at", None) or getattr(sobj, "expire_at", None)
    if created: out["created_at"] = _to_iso(created)
    if last:    out["last_used_at"] = _to_iso(last)
    if exp:     out["expires_at"] = _to_iso(exp)

    # 선택: 클라이언트/리소스 힌트(있으면)
    for k in ("clients", "resources", "services"):
        v = getattr(sobj, k, None)
        if v:
            try:
                # dict | list | set 등 직렬화 가능한 가벼운 요약만
                out[k] = list(v.keys()) if isinstance(v, dict) else list(v)
            except Exception:
                pass
    return out

def _get_registry_from_core() -> Optional[Dict[str, Any]]:
    """
    app.core.session 모듈 안에 존재할 법한 전역 레지스트리를 동적으로 탐지.
    (SESSIONS/_SESSIONS/REGISTRY/_REGISTRY/sessions/_sessions)
    """
    try:
        import app.core.session as core
    except Exception:
        return None

    # 1) 공식 지원 함수가 있으면 사용
    for fname in ("peek_all_sessions", "list_sessions", "get_all_sessions"):
        f = getattr(core, fname, None)
        if callable(f):
            try:
                data = f()
                # dict[str, Any] 또는 list[Any] 둘 다 허용
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    # list면 id를 추출해서 dict로 변환 시도
                    reg: Dict[str, Any] = {}
                    for obj in data:
                        sid = getattr(obj, "id", None) or getattr(obj, "session_id", None)
                        if sid:
                            reg[str(sid)] = obj
                    return reg or None
            except Exception:
                pass

    # 2) 전역 변수 패턴 스캔
    try_names = ("SESSIONS", "_SESSIONS", "REGISTRY", "_REGISTRY", "sessions", "_sessions")
    for name in try_names:
        reg = getattr(core, name, None)
        if isinstance(reg, dict):
            return reg
    return None

def peek_session(session_id: str) -> Dict[str, Any]:
    """
    세션 한 건 조회(생성 없이). 없으면 {"exists": False}
    """
    reg = _get_registry_from_core()
    if not reg:
        return {"exists": False}
    sobj = reg.get(session_id)
    if not sobj:
        return {"exists": False}
    return {"exists": True, "session": _session_to_dict(sobj)}

def list_sessions() -> Dict[str, Any]:
    """
    전체 세션 요약 목록. 없으면 빈 리스트.
    """
    reg = _get_registry_from_core()
    if not reg:
        return {"count": 0, "sessions": []}

    items: List[Dict[str, Any]] = []
    for sid, sobj in reg.items():
        d = _session_to_dict(sobj)
        d["id"] = d.get("id") or sid
        items.append(d)
    return {"count": len(items), "sessions": items}
