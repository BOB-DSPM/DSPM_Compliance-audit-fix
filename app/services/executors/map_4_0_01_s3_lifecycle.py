from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_4_0_01:
    code = "4.0-01"
    title = "S3 Lifecycle rules enabled"

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"checkedBuckets": 0, "nonCompliant": []}

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
                        checked_field="lifecycle_rules",
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
                    reason="No buckets",
                    extract=_extract_meta(),
                )

            for b in buckets:
                name = b["Name"]
                try:
                    cfg = s3.get_bucket_lifecycle_configuration(Bucket=name)
                    rules = cfg.get("Rules", [])
                    enabled = any((r.get("Status") == "Enabled") for r in rules)

                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="LifecycleConfiguration.Rules[].Status",
                        checked_field="rules_enabled_any",
                        comparator="exists",
                        expected_value=True,
                        observed_value=enabled,
                        passed=enabled is True,
                        decision=f"observed {enabled} exists → {'passed' if enabled else 'failed'}",
                        status="COMPLIANT" if enabled else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"rulesCount": len(rules)}
                    ))

                    if not enabled:
                        evidence["nonCompliant"].append(name)

                except botocore.exceptions.ClientError as ie:
                    # NoSuchLifecycleConfiguration → 규칙 없음
                    code = ie.response.get("Error", {}).get("Code")
                    if code in ("NoSuchLifecycleConfiguration", "NoSuchLifecyclePolicy"):
                        evals.append(ServiceEvaluation(
                            service="S3",
                            resource_id=name,
                            evidence_path="LifecycleConfiguration",
                            checked_field="rules_enabled_any",
                            comparator="exists",
                            expected_value=True,
                            observed_value=False,
                            passed=False,
                            decision="no lifecycle configuration → failed",
                            status="NON_COMPLIANT",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))
                        evidence["nonCompliant"].append(name)
                    else:
                        evals.append(ServiceEvaluation(
                            service="S3",
                            resource_id=name,
                            evidence_path="LifecycleConfiguration",
                            checked_field="rules_enabled_any",
                            comparator=None,
                            expected_value=None,
                            observed_value=None,
                            passed=None,
                            decision="cannot evaluate: error",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))

            overall = "COMPLIANT" if not evidence["nonCompliant"] else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall == "COMPLIANT" else "Buckets without enabled lifecycle rules exist",
                extract=_extract_meta(),
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3",
                    resource_id=None,
                    evidence_path="list_buckets",
                    checked_field="buckets",
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
        "code": "4.0-01",
        "category": "4 (데이터 보존/파기/재식별)",
        "service": "S3",
        "console_path": "S3 → 버킷 → Management → Lifecycle",
        "check_how": "Lifecycle rules 존재 및 Enabled 여부",
        "cli_cmd": "aws s3api get-bucket-lifecycle-configuration --bucket BUCKET",
        "return_field": "Rules[].Status",
        "compliant_value": "Enabled",
        "non_compliant_value": "없음/Disabled",
        "console_fix": "버킷 Lifecycle rule 생성(예: 만료/이행 규칙)",
        "cli_fix_cmd": 'aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --lifecycle-configuration \'{"Rules":[{"ID":"Expire90","Status":"Enabled","Expiration":{"Days":90},"Filter":{"Prefix":""}}]}\''
    }
