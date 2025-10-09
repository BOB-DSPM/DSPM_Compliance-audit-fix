from typing import List, Optional, Literal, Any, Dict
from pydantic import BaseModel

Status = Literal["COMPLIANT", "NON_COMPLIANT", "SKIPPED", "ERROR"]
Comparator = Literal["eq","ne","ge","gt","le","lt","contains","exists","regex"]

class ServiceEvaluation(BaseModel):
    service: str
    resource_id: Optional[str] = None
    evidence_path: Optional[str] = None
    checked_field: str
    comparator: Optional[Comparator] = None
    expected_value: Any
    observed_value: Any
    passed: Optional[bool] = None
    decision: Optional[str] = None
    status: Status
    source: Literal["collector", "aws-sdk"]
    extra: Dict[str, Any] = {}

# ✅ 추가: 매핑 메타를 결과에 포함
class MappingExtract(BaseModel):
    code: str
    category: Optional[str] = None
    service: Optional[str] = None
    console_path: Optional[str] = None
    check_how: Optional[str] = None
    cli_cmd: Optional[str] = None
    return_field: Optional[str] = None
    compliant_value: Optional[str] = None
    non_compliant_value: Optional[str] = None
    console_fix: Optional[str] = None
    cli_fix_cmd: Optional[str] = None

class AuditResult(BaseModel):
    mapping_code: str
    title: Optional[str] = None
    status: Status
    evaluations: List[ServiceEvaluation] = []
    evidence: Dict[str, Any] = {}
    reason: Optional[str] = None
    extract: Optional[MappingExtract] = None  # ✅ 여기

class RequirementAuditResponse(BaseModel):
    framework: str
    requirement_id: int
    item_code: str
    results: List[AuditResult]

class BulkAuditResponse(BaseModel):
    framework: str
    total_requirements: int
    executed: int
    results: List[Any]  # RequirementAuditResponse dicts

__all__ = [
    "Status",
    "Comparator",
    "ServiceEvaluation",
    "MappingExtract",
    "AuditResult",
    "RequirementAuditResponse",
    "BulkAuditResponse",
]
