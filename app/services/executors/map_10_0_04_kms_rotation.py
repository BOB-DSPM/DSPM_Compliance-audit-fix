from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_10_0_04:
    """
    10.0-04 KMS 키 회전: 고객 관리형 대칭 키는 자동 회전이 활성화되어야 함.
    제외: AWS 관리형 키, 비대상 스펙(비대칭 등)
    """
    code = "10.0-04"
    title = "KMS 키 자동 회전"

    def audit(self) -> AuditResult:
        kms = boto3.client("kms")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "checkedKeys": 0,
            "nonRotatingKeys": [],
            "skippedKeys": [],
        }

        try:
            paginator = kms.get_paginator("list_keys")
            key_ids: List[str] = []
            for page in paginator.paginate():
                for k in page.get("Keys", []):
                    key_ids.append(k["KeyId"])

            for key_id in key_ids:
                try:
                    meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    key_manager = meta.get("KeyManager")               # CUSTOMER | AWS
                    key_state   = meta.get("KeyState")                 # Enabled, Disabled, ...
                    key_spec    = meta.get("KeySpec")                  # SYMMETRIC_DEFAULT, RSA_2048, ...
                    multi_region= meta.get("MultiRegion")              # bool
                    is_customer = (key_manager == "CUSTOMER")
                    is_enabled  = (key_state == "Enabled")
                    is_symmetric= (key_spec == "SYMMETRIC_DEFAULT")

                    # 회전 대상이 아니면 SKIPPED로 남김
                    if not (is_customer and is_enabled and is_symmetric):
                        evals.append(ServiceEvaluation(
                            service="KMS",
                            resource_id=meta.get("Arn", key_id),
                            evidence_path="KeyMetadata",
                            checked_field="RotationEligible",
                            comparator="exists",
                            expected_value=True,
                            observed_value=False,
                            passed=None,
                            decision="not eligible for rotation (AWS-managed or asymmetric or disabled)",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={
                                "KeyManager": key_manager,
                                "KeySpec": key_spec,
                                "KeyState": key_state,
                                "MultiRegion": multi_region,
                            },
                        ))
                        evidence["skippedKeys"].append(key_id)
                        continue

                    # 대상 키 → 회전 상태 조회
                    rot = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                    passed = bool(rot is True)
                    evals.append(ServiceEvaluation(
                        service="KMS",
                        resource_id=meta.get("Arn", key_id),
                        evidence_path="KeyRotationEnabled",
                        checked_field="KeyRotationEnabled",
                        comparator="eq",
                        expected_value=True,
                        observed_value=rot,
                        passed=passed,
                        decision=f"observed {rot} == True → {'passed' if passed else 'failed'}",
                        status="COMPLIANT" if passed else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={
                            "KeyManager": key_manager,
                            "KeySpec": key_spec,
                            "KeyState": key_state,
                            "MultiRegion": multi_region,
                        },
                    ))
                    evidence["checkedKeys"] += 1
                    if not passed:
                        evidence["nonRotatingKeys"].append(key_id)

                except botocore.exceptions.ClientError as e:
                    # 키 단위 권한 부족/삭제/보존 등 예외 → SKIPPED로 기록
                    evals.append(ServiceEvaluation(
                        service="KMS",
                        resource_id=key_id,
                        evidence_path="KeyRotationEnabled",
                        checked_field="KeyRotationEnabled",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: client error",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(e)},
                    ))
                    evidence["skippedKeys"].append(key_id)

            status = "NON_COMPLIANT" if evidence["nonRotatingKeys"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "10 (비밀/자격증명 관리)",
                    "service": "KMS",
                    "console_path": "KMS → 키 → 구성",
                    "check_how": "get-key-rotation-status",
                    "cli_cmd": "aws kms get-key-rotation-status --key-id KEY_ID",
                    "return_field": "KeyRotationEnabled",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "KMS 키 → 구성에서 자동 회전 활성화",
                    "cli_fix_cmd": "aws kms enable-key-rotation --key-id KEY_ID",
                },
            )

        except botocore.exceptions.ClientError as e:
            # 계정/리전 전체 권한 부족 등 → 엔트리 하나로 SKIPPED 처리
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="KMS",
                    resource_id=None,
                    evidence_path="KeyRotationEnabled",
                    checked_field="KeyRotationEnabled",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                )],
                evidence={},
                reason="Missing permissions",
                extract=None,
            )
