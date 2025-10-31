# app/utils/session_mark.py
from __future__ import annotations
from typing import Any, Dict, Optional
from datetime import datetime, timezone

# 사이드카 저장소(세션 객체에 직접 속성 주입이 안될 때 대비)
_SIDE_CAR: Dict[str, Dict[str, Any]] = {}

def _sid_of(session_obj: Any) -> Optional[str]:
    sid = getattr(session_obj, "id", None) or getattr(session_obj, "session_id", None)
    return str(sid) if sid else None

def mark_session_framework(session_obj: Any, framework: str):
    """
    세션 객체에 가능한 경우 직접 필드를 추가하고,
    안 되면 사이드카에 기록한다.
    """
    sid = _sid_of(session_obj)
    now = datetime.now(timezone.utc)

    # 1) 세션 객체에 직접 주입 시도(동적 속성 허용 시)
    try:
        seen = getattr(session_obj, "frameworks", None)
        if seen is None:
            setattr(session_obj, "frameworks", set([framework]))
        else:
            try:
                seen.add(framework)
            except Exception:
                # 리스트 등으로 되어 있으면 중복체크 후 append
                if framework not in seen:
                    seen.append(framework)
        setattr(session_obj, "last_framework", framework)
        setattr(session_obj, "last_used_at", now)
    except Exception:
        pass

    # 2) 사이드카에도 보조로 저장
    if sid:
        rec = _SIDE_CAR.setdefault(sid, {"frameworks": set(), "counts": {}, "last_framework": None, "last_used_at": None})
        rec["frameworks"].add(framework)
        rec["counts"][framework] = rec["counts"].get(framework, 0) + 1
        rec["last_framework"] = framework
        rec["last_used_at"] = now

def get_session_context(session_id: str) -> Optional[Dict[str, Any]]:
    rec = _SIDE_CAR.get(session_id)
    if not rec:
        return None
    # 직렬화 가능한 형태로 변환
    return {
        "frameworks": sorted(list(rec.get("frameworks", []))),
        "counts": dict(rec.get("counts", {})),
        "last_framework": rec.get("last_framework"),
        "last_used_at": rec.get("last_used_at").isoformat() if rec.get("last_used_at") else None,
    }
