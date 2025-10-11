from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_6_0_02:
    code = "6.0-02"
    title = "SageMaker Model Monitor (스케줄 존재/활성)"

    def audit(self) -> AuditResult:
        sm = boto3.client("sagemaker")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"schedulesChecked": 0, "activeOrScheduled": 0, "statuses": []}

        try:
            paginator = sm.get_paginator("list_monitoring_schedules")
            schedules = []
            for page in paginator.paginate():
                schedules.extend(page.get("MonitoringScheduleSummaries", []))
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="SageMaker", resource_id=None,
                    evidence_path="MonitoringScheduleSummaries", checked_field="MonitoringScheduleStatus",
                    comparator="exists", expected_value=True, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions to list monitoring schedules",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )

        for s in schedules:
            name = s.get("MonitoringScheduleName")
            status = s.get("MonitoringScheduleStatus")
            evidence["schedulesChecked"] += 1
            evidence["statuses"].append({"name": name, "status": status})

            # 기준: "Scheduled" 또는 "Active" 이면 준수
            passed = (status in ("Scheduled", "Active"))
            if passed:
                evidence["activeOrScheduled"] += 1

            evals.append(ServiceEvaluation(
                service="SageMaker",
                resource_id=name,
                evidence_path="MonitoringScheduleSummaries[].MonitoringScheduleStatus",
                checked_field="MonitoringScheduleStatus",
                comparator="regex",
                expected_value="^(Scheduled|Active)$",
                observed_value=status,
                passed=passed,
                decision=f"status {status} matches /^(Scheduled|Active)$/ → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

        if evidence["schedulesChecked"] == 0:
            overall = "NON_COMPLIANT"  # 스케줄이 하나도 없으면 미준수
            reason = "No monitoring schedules"
        else:
            overall = "COMPLIANT" if evidence["activeOrScheduled"] > 0 else "NON_COMPLIANT"
            reason = None if overall == "COMPLIANT" else "No active/scheduled monitoring schedule"

        return AuditResult(
            mapping_code=self.code, title=self.title, status=overall,
            evaluations=evals, evidence=evidence, reason=reason,
            extract={
                "code": self.code, "category": "6 (모델/배포 무결성)", "service": "SageMaker",
                "console_path": "SageMaker → Monitoring",
                "check_how": "MonitoringScheduleStatus 가 Scheduled/Active",
                "cli_cmd": "aws sagemaker list-monitoring-schedules",
                "return_field": "MonitoringScheduleStatus",
                "compliant_value": "Scheduled/Active",
                "non_compliant_value": "없음/그 외",
                "console_fix": "Model Monitor 스케줄 생성/활성",
                "cli_fix_cmd": "aws sagemaker create-monitoring-schedule --monitoring-schedule-name sch --monitoring-schedule-config file://cfg.json"
            }
        )
