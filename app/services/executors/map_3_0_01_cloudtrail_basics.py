from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_01:
    code = "3.0-01"
    title = "CloudTrail (multi-region + validation)"

    def audit(self) -> AuditResult:
        ct = boto3.client("cloudtrail")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"trails": 0, "ok": [], "bad": []}

        try:
            trails = ct.describe_trails().get("trailList", [])
            evidence["trails"] = len(trails)

            for t in trails:
                name = t.get("Name") or t.get("TrailARN", "unknown")
                # 자세 값은 get_trail_status / describe_trails 조합으로 판단
                is_multi = t.get("IsMultiRegionTrail") is True
                # 무결성 검증 플래그는 get_trail_status가 아니라 describe_trails의 LogFileValidationEnabled
                validation = t.get("LogFileValidationEnabled") is True

                passed_multi = is_multi
                passed_validation = validation
                all_pass = passed_multi and passed_validation

                if all_pass:
                    evidence["ok"].append(name)
                else:
                    evidence["bad"].append({"trail": name, "IsMultiRegionTrail": is_multi, "LogFileValidationEnabled": validation})

                evals.append(ServiceEvaluation(
                    service="CloudTrail",
                    resource_id=name,
                    evidence_path="trail.(IsMultiRegionTrail, LogFileValidationEnabled)",
                    checked_field="IsMultiRegionTrail",
                    comparator="eq",
                    expected_value=True,
                    observed_value=is_multi,
                    passed=passed_multi,
                    decision=f"observed {is_multi} == True → {'passed' if passed_multi else 'failed'}",
                    status="COMPLIANT" if passed_multi else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                evals.append(ServiceEvaluation(
                    service="CloudTrail",
                    resource_id=name,
                    evidence_path="trail.LogFileValidationEnabled",
                    checked_field="LogFileValidationEnabled",
                    comparator="eq",
                    expected_value=True,
                    observed_value=validation,
                    passed=passed_validation,
                    decision=f"observed {validation} == True → {'passed' if passed_validation else 'failed'}",
                    status="COMPLIANT" if passed_validation else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            status = "COMPLIANT" if evidence["ok"] else ("SKIPPED" if evidence["trails"] == 0 else "NON_COMPLIANT")
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if status != "SKIPPED" else "No trails found",
                extract={
                    "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "CloudTrail",
                    "console_path": "CloudTrail → Trails",
                    "check_how": "IsMultiRegionTrail & LogFileValidationEnabled",
                    "cli_cmd": "aws cloudtrail describe-trails",
                    "return_field": "IsMultiRegionTrail, LogFileValidationEnabled",
                    "compliant_value": "TRUE, TRUE",
                    "non_compliant_value": "FALSE 포함",
                    "console_fix": "Trails → Edit → Multi-region/Validation 활성",
                    "cli_fix_cmd": "aws cloudtrail update-trail --name TRAIL --is-multi-region-trail --enable-log-file-validation"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudTrail", resource_id=None,
                    evidence_path="trailList", checked_field="IsMultiRegionTrail/LogFileValidationEnabled",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
