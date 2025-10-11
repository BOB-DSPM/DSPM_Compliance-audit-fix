from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_10:
    """
    3.0-10: S3 버전관리(로그 버킷)
    - 기본: 모든 버킷 점검
    - 선택: 태그(log-bucket=true) 또는 이름에 'log' 포함 버킷만 점검하도록 필터 가능
    """
    code = "3.0-10"
    title = "S3 버전관리(로그 버킷)"

    # 필요 시 필터링 전략 조정 (both|tag|name|none)
    FILTER_MODE = "both"   # "both": tag OR name, "tag": tag만, "name": 이름만, "none": 전부
    TAG_KEY = "log-bucket"
    TAG_VALUE = "true"

    def _is_log_bucket(self, s3, bucket_name: str) -> bool:
        if self.FILTER_MODE == "none":
            return True
        is_name_hit = ("log" in bucket_name.lower())
        is_tag_hit = False
        try:
            tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
            for t in tags:
                if t.get("Key") == self.TAG_KEY and str(t.get("Value", "")).lower() == self.TAG_VALUE:
                    is_tag_hit = True
                    break
        except botocore.exceptions.ClientError as e:
            # NoSuchTagSet 등은 태그 없음으로 봄
            if e.response.get("Error", {}).get("Code") not in ("NoSuchTagSet", "NoSuchTagSetError", "NoSuchTagSetException", "NoSuchTagSetExists", "NoSuchTagSetDoesNotExist"):
                # 다른 에러는 무시하고 이름 힌트만 사용
                pass

        if self.FILTER_MODE == "both":
            return is_name_hit or is_tag_hit
        if self.FILTER_MODE == "tag":
            return is_tag_hit
        if self.FILTER_MODE == "name":
            return is_name_hit
        return True

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"checkedBuckets": [], "nonCompliant": []}

        try:
            buckets = s3.list_buckets().get("Buckets", []) or []
            target_buckets = []
            for b in buckets:
                name = b.get("Name")
                if not name:
                    continue
                if self._is_log_bucket(s3, name):
                    target_buckets.append(name)

            # "로그 버킷" 후보가 하나도 안 잡히면 전체 버킷을 검사(보수적으로)
            if not target_buckets:
                target_buckets = [b.get("Name") for b in buckets if b.get("Name")]

            for name in target_buckets:
                status = "None"
                try:
                    vr = s3.get_bucket_versioning(Bucket=name)
                    status = vr.get("Status") or "None"  # Enabled | Suspended | None
                except botocore.exceptions.ClientError as e:
                    # 권한/존재 오류 등은 SKIPPED로 한 줄 남기고 계속
                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="get-bucket-versioning.Status",
                        checked_field="VersioningStatus",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot read bucket versioning",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(e)}
                    ))
                    continue

                passed = (status == "Enabled")
                if not passed:
                    evidence["nonCompliant"].append({"bucket": name, "status": status})

                evals.append(ServiceEvaluation(
                    service="S3",
                    resource_id=name,
                    evidence_path="get-bucket-versioning.Status",
                    checked_field="VersioningStatus",
                    comparator="eq",
                    expected_value="Enabled",
                    observed_value=status,
                    passed=passed,
                    decision=f"observed {status} == Enabled → {'passed' if passed else 'failed'}",
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                evidence["checkedBuckets"].append({"bucket": name, "status": status})

            overall_ok = (len(evidence["nonCompliant"]) == 0) and (len(evidence["checkedBuckets"]) > 0)
            overall_status = "COMPLIANT" if overall_ok else "NON_COMPLIANT"

            # 집계 줄
            evals.append(ServiceEvaluation(
                service="S3",
                resource_id="account/region",
                evidence_path="All targeted log buckets",
                checked_field="All versioning Enabled",
                comparator="eq",
                expected_value=True,
                observed_value=overall_ok,
                passed=overall_ok,
                decision="all targeted buckets have versioning Enabled" if overall_ok
                        else "buckets without Enabled versioning exist",
                status="COMPLIANT" if overall_ok else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"targets": len(evidence["checkedBuckets"]), "nonCompliantCount": len(evidence["nonCompliant"])}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall_status,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall_ok else "Buckets without Enabled versioning exist",
                extract={
                    "code": self.code,
                    "category": "3 (로그/감사/기록 무결성)",
                    "service": "S3",
                    "console_path": "S3 → 버킷 → 속성",
                    "check_how": "get-bucket-versioning.Status",
                    "cli_cmd": "aws s3api get-bucket-versioning --bucket LOG_BUCKET",
                    "return_field": "Status",
                    "compliant_value": "Enabled",
                    "non_compliant_value": "Suspended/없음",
                    "console_fix": "버킷 → Versioning Enable",
                    "cli_fix_cmd": "aws s3api put-bucket-versioning --bucket LOG_BUCKET --versioning-configuration Status=Enabled"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3",
                    resource_id=None,
                    evidence_path="list-buckets",
                    checked_field="prerequisites",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=None
            )
