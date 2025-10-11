from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_6_0_03:
    code = "6.0-03"
    title = "ECR Scan on push 활성화"

    def audit(self) -> AuditResult:
        ecr = boto3.client("ecr")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"reposChecked": 0, "notScanning": []}

        try:
            paginator = ecr.get_paginator("describe_repositories")
            repos = []
            for page in paginator.paginate():
                repos.extend(page.get("repositories", []))
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="ECR", resource_id=None,
                    evidence_path="repositories", checked_field="imageScanningConfiguration.scanOnPush",
                    comparator="exists", expected_value=True, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions to describe repositories",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )

        for r in repos:
            name = r.get("repositoryName")
            conf = (r.get("imageScanningConfiguration") or {})
            scan_on_push = bool(conf.get("scanOnPush"))
            evidence["reposChecked"] += 1
            if not scan_on_push:
                evidence["notScanning"].append(name)

            evals.append(ServiceEvaluation(
                service="ECR",
                resource_id=name,
                evidence_path="repositories[].imageScanningConfiguration.scanOnPush",
                checked_field="imageScanningConfiguration.scanOnPush",
                comparator="eq",
                expected_value=True,
                observed_value=scan_on_push,
                passed=scan_on_push,
                decision=f"observed {scan_on_push} == True → {'passed' if scan_on_push else 'failed'}",
                status="COMPLIANT" if scan_on_push else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

        if evidence["reposChecked"] == 0:
            overall = "SKIPPED"
            reason = "No repositories"
        else:
            overall = "NON_COMPLIANT" if evidence["notScanning"] else "COMPLIANT"
            reason = None if overall == "COMPLIANT" else "Repositories without scanOnPush exist"

        return AuditResult(
            mapping_code=self.code, title=self.title, status=overall,
            evaluations=evals, evidence=evidence, reason=reason,
            extract={
                "code": self.code, "category": "6 (모델/배포 무결성)", "service": "ECR",
                "console_path": "ECR → Repositories",
                "check_how": "imageScanningConfiguration.scanOnPush = true",
                "cli_cmd": "aws ecr describe-repositories --repository-names REPO --query \"repositories[*].imageScanningConfiguration.scanOnPush\"",
                "return_field": "imageScanningConfiguration.scanOnPush",
                "compliant_value": "true",
                "non_compliant_value": "false",
                "console_fix": "리포지토리 설정에서 Scan on push 활성화",
                "cli_fix_cmd": "aws ecr put-image-scanning-configuration --repository-name REPO --image-scanning-configuration scanOnPush=true"
            }
        )
