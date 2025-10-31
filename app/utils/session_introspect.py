# app/utils/session_introspect.py
from __future__ import annotations
from typing import Any, Dict, Optional, List
from datetime import datetime

# ⬇ 추가: 세션 프레임워크 사이드카 컨텍스트 합치기
from app.utils.session_mark import get_session_context

def _to_iso(dt: Any) -> Optional[str]:
    try:
        if isinstance(dt, datetime):
            return dt.isoformat()
        return getattr(dt, "isoformat")()
    except Exception:
        return None

def _session_to_dict(sobj: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in ("id", "session_id", "region", "profile", "ttl_seconds"):
        v = getattr(sobj, k, None)
        if v is not None:
            out[k if k != "session_id" else "id"] = v

    created = getattr(sobj, "created_at", None) or getattr(sobj, "created", None)
    last    = getattr(sobj, "last_used_at", None) or getattr(sobj, "last_used", None)
    exp     = getattr(sobj, "expires_at", None) or getattr(sobj, "expire_at", None)
    if created: out["created_at"] = _to_iso(created)
    if last:    out["last_used_at"] = _to_iso(last)
    if exp:     out["expires_at"] = _to_iso(exp)

    # 프레임워크 정보(세션 객체에 직접 있다면)
    lf = getattr(sobj, "last_framework", None)
    if lf: out["last_framework"] = lf
    fw = getattr(sobj, "frameworks", None)
    if fw:
        try:
            out["frameworks"] = sorted(list(fw)) if not isinstance(fw, list) else sorted(fw)
        except Exception:
            pass

    # 클라이언트/리소스 힌트(있으면)
    for k in ("clients", "resources", "services"):
        v = getattr(sobj, k, None)
        if v:
            try:
                out[k] = list(v.keys()) if isinstance(v, dict) else list(v)
            except Exception:
                pass

    # ⬇ 사이드카에 있는 컨텍스트와 병합(객체에 없을 때 보강)
    sid = out.get("id")
    if sid:
        ctx = get_session_context(str(sid))
        if ctx:
            out.setdefault("frameworks", ctx.get("frameworks"))
            out.setdefault("last_framework", ctx.get("last_framework"))
            out.setdefault("last_used_at", ctx.get("last_used_at"))
            out["framework_counts"] = ctx.get("counts")

    return out

def _get_registry_from_core() -> Optional[Dict[str, Any]]:
    try:
        import app.core.session as core
    except Exception:
        return None

    for fname in ("peek_all_sessions", "list_sessions", "get_all_sessions"):
        f = getattr(core, fname, None)
        if callable(f):
            try:
                data = f()
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    reg: Dict[str, Any] = {}
                    for obj in data:
                        sid = getattr(obj, "id", None) or getattr(obj, "session_id", None)
                        if sid:
                            reg[str(sid)] = obj
                    return reg or None
            except Exception:
                pass

    try_names = ("SESSIONS", "_SESSIONS", "REGISTRY", "_REGISTRY", "sessions", "_sessions")
    for name in try_names:
        reg = getattr(core, name, None)
        if isinstance(reg, dict):
            return reg
    return None

def peek_session(session_id: str) -> Dict[str, Any]:
    reg = _get_registry_from_core()
    if not reg:
        # 레지스트리가 없더라도 사이드카 컨텍스트만이라도 반환
        ctx = get_session_context(session_id)
        if ctx:
            return {"exists": True, "session": {"id": session_id, **ctx}}
        return {"exists": False}
    sobj = reg.get(session_id)
    if not sobj:
        ctx = get_session_context(session_id)
        if ctx:
            return {"exists": True, "session": {"id": session_id, **ctx}}
        return {"exists": False}
    return {"exists": True, "session": _session_to_dict(sobj)}

def list_sessions() -> Dict[str, Any]:
    reg = _get_registry_from_core()
    if not reg:
        return {"count": 0, "sessions": []}
    items: List[Dict[str, Any]] = []
    for sid, sobj in reg.items():
        d = _session_to_dict(sobj)
        d["id"] = d.get("id") or sid
        items.append(d)
    return {"count": len(items), "sessions": items}
