from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_7_0_03:
    code = "7.0-03"
    title = "CloudWatch metric alarms exist"

    def audit(self) -> AuditResult:
        cw = boto3.client("cloudwatch")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"alarmsCount": 0, "sampleAlarms": []}

        try:
            paginator = cw.get_paginator("describe_alarms")
            total = 0
            sample = []

            for page in paginator.paginate():
                alarms = page.get("MetricAlarms", []) or []
                total += len(alarms)
                for a in alarms[:3 - len(sample)]:
                    sample.append(a.get("AlarmName"))

            evidence["alarmsCount"] = total
            evidence["sampleAlarms"] = sample

            passed = total >= 1
            evals.append(ServiceEvaluation(
                service="CloudWatch",
                resource_id="account/region",
                evidence_path="MetricAlarms (count)",
                checked_field="alarms count",
                comparator="ge",
                expected_value=1,
                observed_value=total,
                passed=passed,
                decision=f"observed {total} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            status = "COMPLIANT" if passed else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=None if passed else "No metric alarms",
                extract={
                    "code": self.code, "category": "7 (모니터링/임계치/시간동기화)", "service": "CloudWatch",
                    "console_path": "CloudWatch → Alarms",
                    "check_how": "MetricAlarms >= 1",
                    "cli_cmd": "aws cloudwatch describe-alarms",
                    "return_field": "MetricAlarms",
                    "compliant_value": "존재",
                    "non_compliant_value": "없음",
                    "console_fix": "임계치 경보 생성(CPU 등)",
                    "cli_fix_cmd": "aws cloudwatch put-metric-alarm --alarm-name cpu-high --metric-name CPUUtilization --namespace AWS/EC2 --statistic Average --period 300 --threshold 80 --comparison-operator GreaterThanThreshold --evaluation-periods 2"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudWatch", resource_id=None,
                    evidence_path="describe-alarms",
                    checked_field="MetricAlarms",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
