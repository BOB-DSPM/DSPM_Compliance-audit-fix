# app/core/session.py
from __future__ import annotations

import contextlib
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

# 세션 객체(간단 버전). 필요하면 profile/region 등 필드 확장
@dataclass
class BotoSessionLike:
  id: str
  created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
  last_used_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
  expires_at: Optional[datetime] = None
  profile: Optional[str] = None
  region: Optional[str] = None

  def touch(self):
    self.last_used_at = datetime.now(timezone.utc)

# 전역 레지스트리(간단 캐시)
_SESSIONS: Dict[str, BotoSessionLike] = {}

def get_or_create_session(session_id: str) -> BotoSessionLike:
  s = _SESSIONS.get(session_id)
  if s is None:
    s = BotoSessionLike(id=session_id, expires_at=datetime.now(timezone.utc) + timedelta(hours=2))
    _SESSIONS[session_id] = s
  s.touch()
  return s

def peek_all_sessions() -> Dict[str, BotoSessionLike]:
  return _SESSIONS

# 현재 컨텍스트의 세션
CURRENT_BOTO3_SESSION: ContextVar[Optional[BotoSessionLike]] = ContextVar("CURRENT_BOTO3_SESSION", default=None)

@contextlib.contextmanager
def use_session(session: BotoSessionLike):
  """
  제너레이터/스트리밍에서도 안전하게 reset 되도록 ValueError 무시 처리.
  """
  tok = CURRENT_BOTO3_SESSION.set(session)
  try:
    yield
  finally:
    try:
      CURRENT_BOTO3_SESSION.reset(tok)
    except ValueError:
      # 스트리밍 제너레이터의 GC/파이널라이저가 다른 컨텍스트에서 호출된 케이스
      pass
