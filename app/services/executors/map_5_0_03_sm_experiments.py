from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_03:
    code = "5.0-03"
    title = "SageMaker Experiments 존재 여부"

    def audit(self) -> AuditResult:
        sm = boto3.client("sagemaker")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"experimentsCount": 0, "sample": []}

        try:
            paginator = sm.get_paginator("list_experiments")
            items = []
            for page in paginator.paginate():
                items.extend(page.get("ExperimentSummaries", []) or [])

            evidence["experimentsCount"] = len(items)
            evidence["sample"] = [it.get("ExperimentName") for it in items[:5]]

            passed = evidence["experimentsCount"] >= 1
            evals.append(ServiceEvaluation(
                service="SageMaker",
                resource_id="region",
                evidence_path="ExperimentSummaries",
                checked_field="Experiments count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["experimentsCount"],
                passed=passed,
                decision=f"observed {evidence['experimentsCount']} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code, "category": "5 (데이터 품질/출처/라인리지)", "service": "SageMaker",
                    "console_path": "SageMaker → Experiments",
                    "check_how": "ExperimentSummaries 존재 여부",
                    "cli_cmd": "aws sagemaker list-experiments",
                    "return_field": "ExperimentSummaries",
                    "compliant_value": "존재(>=1)", "non_compliant_value": "없음(0)",
                    "console_fix": "SageMaker Studio에서 새 Experiment 생성",
                    "cli_fix_cmd": "aws sagemaker create-experiment --experiment-name exp1"
                }
            )
        except botocore.exceptions.ClientError as e:
            evals.append(ServiceEvaluation(
                service="SageMaker", resource_id=None,
                evidence_path="ExperimentSummaries", checked_field="Experiments count",
                comparator="ge", expected_value=1,
                observed_value=None, passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, title=self.title, status="SKIPPED",
                               evaluations=evals, evidence={}, reason="Missing permissions or API error", extract=None)
