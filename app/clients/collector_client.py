# app/clients/collector_client.py
import httpx
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, AnyHttpUrl
from app.core.config import settings

class CollectorClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url: str = base_url or "http://localhost:8000"
        self._client = httpx.Client(timeout=30.0)

    # ---- 목록 API (필요 시 확장) ----
    def list_s3_buckets(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/s3-buckets")
        r.raise_for_status()
        return r.json()

    def list_dynamodb_tables(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/dynamodb-tables")
        r.raise_for_status()
        return r.json()

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/rds-instances")
        r.raise_for_status()
        return r.json()

    def list_redshift_clusters(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/redshift-clusters")
        r.raise_for_status()
        return r.json()

    def list_efs_filesystems(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/efs-filesystems")
        r.raise_for_status()
        return r.json()

    def list_elasticache_clusters(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/elasticache-clusters")
        r.raise_for_status()
        return r.json()

    def list_kinesis_streams(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/kinesis-streams")
        r.raise_for_status()
        return r.json()

    def list_msk_clusters(self) -> List[Dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/api/msk-clusters")
        r.raise_for_status()
        return r.json()

    # ---- 상세 API (필요 시 확장) ----
    def get_s3_bucket(self, name: str) -> Dict[str, Any]:
        r = self._client.get(f"{self.base_url}/api/repositories/s3/{name}")
        r.raise_for_status()
        return r.json()

    def get_rds_instance(self, db_id: str) -> Dict[str, Any]:
        r = self._client.get(f"{self.base_url}/api/repositories/rds/{db_id}")
        r.raise_for_status()
        return r.json()
