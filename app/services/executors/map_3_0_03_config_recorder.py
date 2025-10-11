from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_03:
    code = "3.0-03"
    title = "AWS Config recorder running"

    def audit(self) -> AuditResult:
        cfg = boto3.client("config")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"recorders": []}

        try:
            stats = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", []) or []
            has_running = False

            for st in stats:
                name = st.get("name") or "default"
                rec = bool(st.get("recording", False))
                evidence["recorders"].append({"name": name, "recording": rec})

                evals.append(ServiceEvaluation(
                    service="AWS Config",
                    resource_id=name,
                    evidence_path="ConfigurationRecordersStatus[].recording",
                    checked_field="recording",
                    comparator="eq",
                    expected_value=True,
                    observed_value=rec,
                    passed=rec,
                    decision=f"observed {rec} == True → {'passed' if rec else 'failed'}",
                    status="COMPLIANT" if rec else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                has_running = has_running or rec

            if not stats:
                # 레코더 자체가 없으면 비준수
                evals.append(ServiceEvaluation(
                    service="AWS Config",
                    resource_id="(none)",
                    evidence_path="ConfigurationRecordersStatus",
                    checked_field="recorders count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=0,
                    passed=False,
                    decision="observed 0 >= 1 → failed",
                    status="NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            status = "COMPLIANT" if has_running else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence,
                reason=None if status == "COMPLIANT" else "No running recorder",
                extract={
                    "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "AWS Config",
                    "console_path": "Config → Recorder/Rules",
                    "check_how": "describe-configuration-recorder-status.recording == true",
                    "cli_cmd": "aws configservice describe-configuration-recorder-status",
                    "return_field": "recording",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "Config → Start recorder",
                    "cli_fix_cmd": "aws configservice start-configuration-recorder --configuration-recorder-name default"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="AWS Config", resource_id=None,
                    evidence_path="describe-configuration-recorder-status",
                    checked_field="recording",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
