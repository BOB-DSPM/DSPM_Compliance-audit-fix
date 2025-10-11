from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_4_0_02:
    code = "4.0-02"
    title = "S3 Object Lock (WORM) enabled"

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "checkedBuckets": 0,
            "enabled": [],
            "disabled": [],
        }

        try:
            buckets = s3.list_buckets().get("Buckets", [])
            evidence["checkedBuckets"] = len(buckets)

            if not buckets:
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="S3",
                        resource_id=None,
                        evidence_path="Buckets",
                        checked_field="ObjectLockEnabled",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="no buckets → cannot evaluate",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={}
                    )],
                    evidence=evidence,
                    reason="No S3 buckets",
                    extract=_extract_meta(),
                )

            for b in buckets:
                name = b["Name"]
                observed = "DISABLED"
                passed = False

                try:
                    resp = s3.get_object_lock_configuration(Bucket=name)
                    conf = resp.get("ObjectLockConfiguration") or {}
                    # API가 활성화된 버킷은 'ObjectLockEnabled': 'Enabled' 를 반환
                    observed = conf.get("ObjectLockEnabled", "DISABLED")
                    passed = (observed == "Enabled")
                except botocore.exceptions.ClientError as ie:
                    # 비활성 버킷은 보통 NoSuch/ObjectLockConfigurationNotFound 오류
                    code = ie.response.get("Error", {}).get("Code", "")
                    if code in ("ObjectLockConfigurationNotFoundError",
                                "NoSuchObjectLockConfiguration",
                                "InvalidRequest",
                                "NoSuchBucket"):
                        observed = "DISABLED"
                        passed = False
                    else:
                        evals.append(ServiceEvaluation(
                            service="S3",
                            resource_id=name,
                            evidence_path="GetObjectLockConfiguration",
                            checked_field="ObjectLockEnabled",
                            comparator=None,
                            expected_value=None,
                            observed_value=None,
                            passed=None,
                            decision="cannot evaluate: error",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))
                        # 다른 예외는 평가 제외(Skipped)하고 다음 버킷으로
                        continue

                if passed:
                    evidence["enabled"].append(name)
                else:
                    evidence["disabled"].append(name)

                evals.append(ServiceEvaluation(
                    service="S3",
                    resource_id=name,
                    evidence_path="ObjectLockConfiguration.ObjectLockEnabled",
                    checked_field="ObjectLockEnabled",
                    comparator="eq",
                    expected_value="Enabled",
                    observed_value=observed,
                    passed=passed,
                    decision=f"observed {observed} == Enabled → {'passed' if passed else 'failed'}",
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            overall = "COMPLIANT" if not evidence["disabled"] else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall == "COMPLIANT" else "Buckets without Object Lock enabled exist",
                extract=_extract_meta(),
            )

        except botocore.exceptions.ClientError as e:
            # list_buckets 자체 권한 없음 등
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3",
                    resource_id=None,
                    evidence_path="ListBuckets",
                    checked_field="Buckets",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=_extract_meta(),
            )


def _extract_meta() -> Dict[str, Any]:
    return {
        "code": "4.0-02",
        "category": "4 (데이터 보존/파기/재식별)",
        "service": "S3 Object Lock",
        "console_path": "S3 → Object Lock",
        "check_how": "ObjectLockEnabled == Enabled",
        "cli_cmd": "aws s3api get-object-lock-configuration --bucket BUCKET",
        "return_field": "ObjectLockConfiguration.ObjectLockEnabled",
        "compliant_value": "Enabled",
        "non_compliant_value": "DISABLED/Not configured",
        "console_fix": "Object Lock 지원 버킷 생성 후 마이그레이션(생성 시에만 활성 가능)",
        "cli_fix_cmd": "-",  # 기존 버킷엔 활성 불가
    }
