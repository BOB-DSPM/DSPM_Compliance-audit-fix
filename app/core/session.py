# app/core/session.py
from __future__ import annotations
import time
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Dict, Optional

import boto3
import httpx

# 요청 처리 중 사용할 현재 세션(컨텍스트)
CURRENT_BOTO3_SESSION: ContextVar[Optional[boto3.session.Session]] = ContextVar(
    "CURRENT_BOTO3_SESSION", default=None
)
CURRENT_HTTPX_CLIENT: ContextVar[Optional[httpx.Client]] = ContextVar(
    "CURRENT_HTTPX_CLIENT", default=None
)

class AuditSession:
    """
    - boto3.Session / httpx.Client 재사용
    - 간단 TTL(세션 수명) 관리
    """
    def __init__(self, session_id: str, *, region: Optional[str], profile: Optional[str], ttl_seconds: int = 600):
        self.id = session_id
        self.region = region
        self.profile = profile
        self.created_at = int(time.time())
        self.ttl = max(0, int(ttl_seconds))  # 0이면 만료 관리 안함

        # boto3 세션과 httpx 커넥션 풀
        self.boto3 = boto3.session.Session(profile_name=profile, region_name=region)
        self.http = httpx.Client(timeout=30.0)

        # 서비스별 클라이언트 캐시
        self._clients: Dict[str, any] = {}
        self._lock = threading.Lock()

    def is_expired(self) -> bool:
        if self.ttl == 0:
            return False
        return (int(time.time()) - self.created_at) > self.ttl

    def client(self, service: str):
        with self._lock:
            if service not in self._clients:
                self._clients[service] = self.boto3.client(service, region_name=self.region)
            return self._clients[service]

    def close(self):
        try:
            self.http.close()
        except Exception:
            pass
        self._clients.clear()

# 전역 세션 레지스트리
_SESSIONS: Dict[str, AuditSession] = {}
_LOCK = threading.Lock()

def create_session(session_id: str, *, region: Optional[str], profile: Optional[str], ttl_seconds: int = 600) -> AuditSession:
    with _LOCK:
        s = AuditSession(session_id, region=region, profile=profile, ttl_seconds=ttl_seconds)
        _SESSIONS[session_id] = s
        return s

def get_session(session_id: str) -> Optional[AuditSession]:
    with _LOCK:
        s = _SESSIONS.get(session_id)
        if s and s.is_expired():
            # 만료 시 정리
            s.close()
            _SESSIONS.pop(session_id, None)
            return None
        return s

def ensure_session(session_id: str, *, region: Optional[str], profile: Optional[str], ttl_seconds: int = 600) -> AuditSession:
    s = get_session(session_id)
    if s:
        return s
    return create_session(session_id, region=region, profile=profile, ttl_seconds=ttl_seconds)

def end_session(session_id: str) -> None:
    with _LOCK:
        s = _SESSIONS.pop(session_id, None)
        if s:
            s.close()

@contextmanager
def use_session(session: AuditSession):
    """
    이 컨텍스트 안에서는 app.core.aws / http 클라이언트들이 동일 세션을 재사용
    """
    tok1 = CURRENT_BOTO3_SESSION.set(session.boto3)
    tok2 = CURRENT_HTTPX_CLIENT.set(session.http)
    try:
        yield session
    finally:
        CURRENT_BOTO3_SESSION.reset(tok1)
        CURRENT_HTTPX_CLIENT.reset(tok2)