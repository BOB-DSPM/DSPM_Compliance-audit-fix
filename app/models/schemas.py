from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# 공용 리터럴/타입
# -----------------------------------------------------------------------------
Status = Literal["COMPLIANT", "NON_COMPLIANT", "SKIPPED", "ERROR"]
Comparator = Literal["eq", "ne", "ge", "gt", "le", "lt", "contains", "exists", "regex"]

# -----------------------------------------------------------------------------
# (원래 show_schemas.py 에 있던) Mapping/Requirement 조회용 스키마
#   - Mapping API (localhost:8003) 응답 파싱용
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# (감사 API 응답) 평가/증적/결과 스키마
# -----------------------------------------------------------------------------
class ServiceEvaluation(BaseModel):
    service: str                              # 예: "S3", "CloudFront", "IAM"
    resource_id: Optional[str] = None         # 예: 버킷명, 배포 ARN, etc
    evidence_path: Optional[str] = None       # 어떤 경로/필드를 증적 삼았는지
    checked_field: str                        # 예: "Default SSE Algorithm"
    comparator: Optional[Comparator] = None   # eq, ge, contains ...
    expected_value: Any                       # 기대값/기준
    observed_value: Any                       # 실제 관측값
    passed: Optional[bool] = None             # 비교 통과 여부 (연산 가능한 경우)
    decision: Optional[str] = None            # 사람이 읽을 수 있는 비교결과 설명
    status: Status                            # 이 리소스 단위 판정
    source: Literal["collector", "aws-sdk"]   # 어디서 조회했는지
    extra: Dict[str, Any] = Field(default_factory=dict)  # 원문/추가 정보


class MappingExtract(BaseModel):
    # 매핑 메타(설명) 일부를 결과에 함께 첨부하고 싶을 때
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
    extract: Optional[MappingExtract] = None


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
