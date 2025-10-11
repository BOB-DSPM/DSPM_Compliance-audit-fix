from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_04:
    code = "3.0-04"
    title = "CloudWatch Logs retention >= 30d"

    def audit(self) -> AuditResult:
        logs = boto3.client("logs")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"totalLogGroups": 0, "nonCompliant": []}

        try:
            paginator = logs.get_paginator("describe_log_groups")
            groups = []
            for page in paginator.paginate():
                groups.extend(page.get("logGroups", []))

            evidence["totalLogGroups"] = len(groups)
            for g in groups:
                name = g.get("logGroupName")
                r = g.get("retentionInDays", 0) or 0
                passed = (r >= 30)
                if not passed:
                    evidence["nonCompliant"].append({"logGroup": name, "retentionInDays": r})

                evals.append(ServiceEvaluation(
                    service="CloudWatch Logs",
                    resource_id=name,
                    evidence_path="logGroups[].retentionInDays",
                    checked_field="retentionInDays",
                    comparator="ge",
                    expected_value=30,
                    observed_value=r,
                    passed=passed,
                    decision=f"observed {r} >= 30 → {'passed' if passed else 'failed'}",
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            if evidence["totalLogGroups"] == 0:
                status = "SKIPPED"
                reason = "No log groups"
            else:
                status = "COMPLIANT" if not evidence["nonCompliant"] else "NON_COMPLIANT"
                reason = None

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=reason,
                extract={
                    "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "CloudWatch Logs",
                    "console_path": "CloudWatch → 로그 그룹",
                    "check_how": "보존기간 설정(≥30)",
                    "cli_cmd": "aws logs describe-log-groups --query 'logGroups[*].retentionInDays'",
                    "return_field": "retentionInDays",
                    "compliant_value": ">=30",
                    "non_compliant_value": "0/없음",
                    "console_fix": "Log group → Edit retention",
                    "cli_fix_cmd": "aws logs put-retention-policy --log-group-name LOG_GROUP --retention-in-days 90"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudWatch Logs", resource_id=None,
                    evidence_path="logGroups", checked_field="retentionInDays",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
