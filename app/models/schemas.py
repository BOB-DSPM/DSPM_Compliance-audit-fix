# app/models/schemas.py
from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Status = Literal["COMPLIANT", "NON_COMPLIANT", "SKIPPED", "ERROR"]
Comparator = Literal["eq", "ne", "ge", "gt", "le", "lt", "contains", "exists", "regex"]

# ---- Mapping API 응답 파싱용 ----
class FrameworkCountOut(BaseModel):
    framework: str
    count: int

class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str] = None
    title: str
    mapping_status: Optional[str] = None

class MappingOut(BaseModel):
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

class RequirementDetailOut(BaseModel):
    framework: str
    requirement: RequirementRowOut
    mappings: List[MappingOut]

# ---- 감사 응답용 ----
class ServiceEvaluation(BaseModel):
    service: str
    resource_id: Optional[str] = None
    evidence_path: Optional[str] = None
    checked_field: str
    comparator: Optional[Comparator] = None
    expected_value: Any = None
    observed_value: Any = None
    passed: Optional[bool] = None
    decision: Optional[str] = None
    status: Status
    source: Literal["collector", "aws-sdk"]
    extra: Dict[str, Any] = Field(default_factory=dict)

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
    evaluations: List[ServiceEvaluation] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None
    extract: Optional[Dict[str, Any]] = None

class RequirementAuditResponse(BaseModel):
    framework: str
    requirement_id: int
    item_code: str
    results: List[AuditResult]
    requirement_status: Status
    summary: Dict[str, int]

class BulkAuditResponse(BaseModel):
    framework: str
    total_requirements: int
    executed: int
    results: List[Any]  # res.dict()를 넣을 때는 Any 유지
