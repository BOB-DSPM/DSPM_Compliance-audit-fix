from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_08:
    code = "3.0-08"
    title = "CloudFront logging enabled"

    def audit(self) -> AuditResult:
        cf = boto3.client("cloudfront")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"totalDistributions": 0, "nonCompliant": []}

        try:
            # 배포 목록 조회 (요약에는 Logging이 없을 수 있어 개별 Config 호출)
            dist_ids: List[str] = []
            marker = None
            while True:
                kwargs = {"MaxItems": "100"}
                if marker:
                    kwargs["Marker"] = marker
                resp = cf.list_distributions(**kwargs)
                dist_list = resp.get("DistributionList", {})
                items = dist_list.get("Items", []) or []
                for d in items:
                    dist_ids.append(d["Id"])
                if dist_list.get("IsTruncated"):
                    marker = dist_list.get("NextMarker")
                else:
                    break

            evidence["totalDistributions"] = len(dist_ids)

            for did in dist_ids:
                try:
                    cfg = cf.get_distribution_config(Id=did)["DistributionConfig"]
                    logging = cfg.get("Logging", {}) or {}
                    enabled = bool(logging.get("Enabled", False))

                    passed = enabled
                    if not passed:
                        evidence["nonCompliant"].append(did)

                    evals.append(ServiceEvaluation(
                        service="CloudFront",
                        resource_id=did,
                        evidence_path="DistributionConfig.Logging.Enabled",
                        checked_field="Logging.Enabled",
                        comparator="eq",
                        expected_value=True,
                        observed_value=enabled,
                        passed=passed,
                        decision=f"observed {enabled} == True → {'passed' if passed else 'failed'}",
                        status="COMPLIANT" if passed else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="CloudFront",
                        resource_id=did,
                        evidence_path="GetDistributionConfig",
                        checked_field="Logging.Enabled",
                        comparator=None, expected_value=None, observed_value=None, passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED", source="aws-sdk", extra={"error": str(ie)}
                    ))

            if evidence["totalDistributions"] == 0:
                status, reason = "SKIPPED", "No distributions"
            else:
                status, reason = ("COMPLIANT", None) if not evidence["nonCompliant"] else ("NON_COMPLIANT", None)

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=reason,
                extract={
                    "code": self.code,
                    "category": "3 (로그/감사/기록 무결성)",
                    "service": "CloudFront",
                    "console_path": "CloudFront → 배포 → 설정",
                    "check_how": "표준/실시간 로그 설정 Enabled",
                    "cli_cmd": "aws cloudfront get-distribution-config --id DIST_ID",
                    "return_field": "DistributionConfig.Logging.Enabled",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "CloudFront → Enable logging → S3 지정",
                    "cli_fix_cmd": "aws cloudfront update-distribution --id DIST_ID --if-match ETag --distribution-config file://cfg.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudFront", resource_id=None,
                    evidence_path="DistributionList", checked_field="Logging.Enabled",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
