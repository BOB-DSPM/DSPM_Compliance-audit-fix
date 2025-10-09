from typing import Dict, Type, Optional, Protocol
from app.models.schemas import AuditResult
from app.services.executors.map_1_0_01_sso_permission_sets import Exec_1_0_01
from app.services.executors.map_1_0_02_org_scp import Exec_1_0_02
from app.services.executors.map_1_0_06_root_mfa import Exec_1_0_06
from app.services.executors.map_11_0_02_config_conformance_pack import Exec_11_0_02
from app.services.executors.map_2_0_01_s3_sse_kms import Exec_2_0_01
from app.services.executors.map_2_0_15_cloudfront_https import Exec_2_0_15

class Auditable(Protocol):
    code: str
    def audit(self) -> AuditResult: ...

EXECUTOR_REGISTRY: Dict[str, Type[Auditable]] = {
    "1.0-01": Exec_1_0_01,
    "1.0-02": Exec_1_0_02,
    "1.0-06": Exec_1_0_06,
    "11.0-02": Exec_11_0_02,
    "2.0-01": Exec_2_0_01,
    "2.0-15": Exec_2_0_15,
}

def make_executor(mapping_code: str) -> Optional[Auditable]:
    cls = EXECUTOR_REGISTRY.get(mapping_code)
    return cls() if cls else None
