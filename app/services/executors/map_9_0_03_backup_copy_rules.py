from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_9_0_03:
    code = "9.0-03"
    title = "AWS Backup DR 카피 규칙 존재 여부"

    def audit(self) -> AuditResult:
        backup = boto3.client("backup")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"copyJobsCount": 0, "sampleJobIds": []}

        try:
            paginator = backup.get_paginator("list_copy_jobs")
            jobs = []
            for page in paginator.paginate():
                jobs.extend(page.get("CopyJobs", []) or [])
            evidence["copyJobsCount"] = len(jobs)
            evidence["sampleJobIds"] = [j.get("CopyJobId") for j in jobs[:5]]

            passed = evidence["copyJobsCount"] >= 1
            evals.append(ServiceEvaluation(
                service="AWS Backup",
                resource_id="account/region",
                evidence_path="CopyJobs[].CopyJobId",
                checked_field="CopyJobs count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["copyJobsCount"],
                passed=passed,
                decision=f"observed {evidence['copyJobsCount']} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            return AuditResult(
                mapping_code=self.code, title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category":"9 (백업/복구/DR)","service":"AWS Backup",
                    "console_path":"AWS Backup → Backup plans",
                    "check_how":"list-copy-jobs → CopyJobs 존재 여부",
                    "cli_cmd":"aws backup list-copy-jobs",
                    "return_field":"CopyJobs",
                    "compliant_value":"존재(>=1)", "non_compliant_value":"없음(0)",
                    "console_fix":"Backup plan 편집에서 Copy to destination(교차 리전/계정) 추가",
                    "cli_fix_cmd":"aws backup update-backup-plan --backup-plan-id ID --backup-plan file://plan-with-copy.json"
                }
            )
        except botocore.exceptions.ClientError as e:
            evals.append(ServiceEvaluation(
                service="AWS Backup", resource_id=None, evidence_path="CopyJobs",
                checked_field="CopyJobs count", comparator="ge", expected_value=1,
                observed_value=None, passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, title=self.title, status="SKIPPED",
                               evaluations=evals, evidence={}, reason="Missing permissions or API error", extract=None)
