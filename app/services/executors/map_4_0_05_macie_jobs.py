from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_4_0_05:
    code = "4.0-05"
    title = "Amazon Macie: classification jobs exist"

    def audit(self) -> AuditResult:
        macie = boto3.client("macie2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"jobsCount": 0, "sampleJobs": []}

        try:
            total = 0
            sample: List[str] = []
            next_token = None

            while True:
                resp = macie.list_classification_jobs(maxResults=50, nextToken=next_token) if next_token else macie.list_classification_jobs(maxResults=50)
                jobs = resp.get("items", []) or resp.get("classificationJobs", []) or []
                total += len(jobs)
                for j in jobs:
                    if len(sample) < 3:
                        name = j.get("name") or j.get("jobId")
                        if name: sample.append(name)
                next_token = resp.get("nextToken")
                if not next_token:
                    break

            evidence["jobsCount"] = total
            evidence["sampleJobs"] = sample

            passed = total >= 1
            evals.append(ServiceEvaluation(
                service="Macie",
                resource_id="account/region",
                evidence_path="ClassificationJobs (count)",
                checked_field="jobs count",
                comparator="ge",
                expected_value=1,
                observed_value=total,
                passed=passed,
                decision=f"observed {total} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            return AuditResult(
                mapping_code=self.code, title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals, evidence=evidence,
                reason=None if passed else "No Macie classification jobs",
                extract={
                    "code": self.code, "category":"4 (데이터 보존/파기/재식별)", "service":"Amazon Macie",
                    "console_path":"Macie → Jobs",
                    "check_how":"list-classification-jobs >= 1",
                    "cli_cmd":"aws macie2 list-classification-jobs",
                    "return_field":"items[].jobId/status",
                    "compliant_value":"COMPLETE/RUNNING 존재",
                    "non_compliant_value":"없음",
                    "console_fix":"스캔 Job 생성 후 버킷 지정",
                    "cli_fix_cmd":"aws macie2 create-classification-job --job-type ONE_TIME --name dspm-pii-scan --s3-job-definition bucketDefinitions=[{accountId=ACC,buckets=[BUCKET]}]"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Macie", resource_id=None,
                    evidence_path="list-classification-jobs",
                    checked_field="items",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
