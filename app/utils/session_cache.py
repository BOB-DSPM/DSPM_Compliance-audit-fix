from __future__ import annotations
import os, time, threading, json, hashlib
from typing import Any, Optional, Tuple

DEFAULT_TTL_SEC = int(os.getenv("SESSION_TTL_SEC", "600"))
MAX_ITEMS = int(os.getenv("SESSION_CACHE_MAX", "512"))

REDIS_URL = os.getenv("REDIS_URL")
_r = None
if REDIS_URL:
    try:
        import redis  # type: ignore
        _r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        _r = None

class _TTLCache:
    def __init__(self, ttl: int = DEFAULT_TTL_SEC, max_items: int = MAX_ITEMS):
        self.ttl = ttl
        self.max_items = max_items
        self._store: dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def _gc(self):
        now = time.time()
        for k, (exp, _) in list(self._store.items()):
            if exp < now:
                self._store.pop(k, None)
        if len(self._store) > self.max_items:
            items = sorted(self._store.items(), key=lambda kv: kv[1][0])
            for k, _ in items[: len(self._store) - self.max_items]:
                self._store.pop(k, None)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            self._gc()
            v = self._store.get(key)
            return None if not v else v[1]

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        ttl = self.ttl if ttl is None else ttl
        with self._lock:
            self._store[key] = (time.time() + ttl, value)
            self._gc()

_mem = _TTLCache()

def make_cache_key(path: str, method: str, query: dict[str, Any], body: Any = None, session_id: str | None = None) -> str:
    payload = {
        "m": (method or "GET").upper(),
        "p": path or "/",
        "q": sorted((query or {}).items()),
        "b": body if isinstance(body, (str, int, float, type(None))) else None,
        "sid": session_id,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "RESP:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

def cache_get(key: str) -> Optional[Any]:
    if _r:
        raw = _r.get(key)
        return json.loads(raw) if raw else None
    return _mem.get(key)

def cache_set(key: str, value: Any, ttl: Optional[int] = None):
    ttl = DEFAULT_TTL_SEC if ttl is None else ttl
    if _r:
        _r.set(key, json.dumps(value, ensure_ascii=False), ex=ttl)
    else:
        _mem.set(key, value, ttl=ttl)

def cache_clear(prefix: str | None = None):
    if _r:
        pat = (prefix or "RESP:") + "*"
        for k in _r.scan_iter(pat):  # type: ignore[attr-defined]
            _r.delete(k)
    else:
        _mem._store.clear()
