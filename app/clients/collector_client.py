# app/clients/collector_client.py
from __future__ import annotations
import httpx
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.core.session import CURRENT_HTTPX_CLIENT

class CollectorClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url: str = (base_url or f"{settings.COLLECTOR_BASE_URL}").rstrip("/")

    def _http(self) -> httpx.Client:
        cli = CURRENT_HTTPX_CLIENT.get()
        return cli if cli is not None else httpx.Client(timeout=30.0)

    # ---- 목록 API (필요 시 확장) ----
    def list_s3_buckets(self) -> List[Dict[str, Any]]:
        h = self._http()
        close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/s3-buckets")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_dynamodb_tables(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/dynamodb-tables")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/rds-instances")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_redshift_clusters(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/redshift-clusters")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_efs_filesystems(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/efs-filesystems")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_elasticache_clusters(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/elasticache-clusters")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_kinesis_streams(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/kinesis-streams")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def list_msk_clusters(self) -> List[Dict[str, Any]]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/msk-clusters")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    # ---- 상세 API (필요 시 확장) ----
    def get_s3_bucket(self, name: str) -> Dict[str, Any]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/repositories/s3/{name}")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass

    def get_rds_instance(self, db_id: str) -> Dict[str, Any]:
        h = self._http(); close_needed = (h is not CURRENT_HTTPX_CLIENT.get())
        try:
            r = h.get(f"{self.base_url}/api/repositories/rds/{db_id}")
            r.raise_for_status()
            return r.json()
        finally:
            if close_needed:
                try: h.close()
                except Exception: pass
