from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_01:
    code = "5.0-01"
    title = "DataBrew: projects exist (profiling/quality)"

    def audit(self) -> AuditResult:
        brew = boto3.client("databrew")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"projectsCount": 0, "sampleProjects": []}

        try:
            total = 0
            sample: List[str] = []

            try:
                paginator = brew.get_paginator("list_projects")
                pages = paginator.paginate()
            except botocore.exceptions.OperationNotPageableError:
                pages = []
                next_token = None
                while True:
                    resp = brew.list_projects(MaxResults=100, NextToken=next_token) if next_token else brew.list_projects(MaxResults=100)
                    pages.append(resp)
                    next_token = resp.get("NextToken")
                    if not next_token:
                        break

            for page in pages:
                items = page.get("Projects", []) or []
                total += len(items)
                for it in items:
                    if len(sample) < 3:
                        name = it.get("Name")
                        if name: sample.append(name)

            evidence["projectsCount"] = total
            evidence["sampleProjects"] = sample

            passed = total >= 1
            evals.append(ServiceEvaluation(
                service="Glue DataBrew",
                resource_id="account/region",
                evidence_path="Projects (count)",
                checked_field="projects count",
                comparator="ge",
                expected_value=1,
                observed_value=total,
                passed=passed,
                decision=f"observed {total} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="collector",
                extra={}
            ))

            return AuditResult(
                mapping_code=self.code, title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals, evidence=evidence,
                reason=None if passed else "No DataBrew projects",
                extract={
                    "code": self.code, "category":"5 (데이터 품질/출처/라인리지)", "service":"Glue DataBrew",
                    "console_path":"DataBrew → Projects",
                    "check_how":"list-projects >= 1",
                    "cli_cmd":"aws databrew list-projects",
                    "return_field":"Projects",
                    "compliant_value":"존재",
                    "non_compliant_value":"없음",
                    "console_fix":"프로파일링/품질 프로젝트 생성",
                    "cli_fix_cmd":"aws databrew create-project --name dq --dataset-name ds --recipe-name rc --role-arn ARN"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Glue DataBrew", resource_id=None,
                    evidence_path="list-projects",
                    checked_field="Projects",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
