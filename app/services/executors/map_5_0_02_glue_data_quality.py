from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_02:
    code = "5.0-02"
    title = "Glue Data Quality: rulesets exist"

    def audit(self) -> AuditResult:
        glue = boto3.client("glue")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"rulesetCount": 0, "sampleRulesets": []}

        try:
            total = 0
            sample: List[str] = []

            # paginator 있으면 사용, 없으면 수동 루프
            try:
                paginator = glue.get_paginator("list_data_quality_rulesets")
                pages = paginator.paginate()
            except botocore.exceptions.OperationNotPageableError:
                pages = []
                next_token = None
                while True:
                    resp = glue.list_data_quality_rulesets(MaxResults=100, NextToken=next_token) if next_token else glue.list_data_quality_rulesets(MaxResults=100)
                    pages.append(resp)
                    next_token = resp.get("NextToken")
                    if not next_token:
                        break

            for page in pages:
                items = page.get("Rulesets", []) or []
                total += len(items)
                for it in items:
                    if len(sample) < 3:
                        name = it.get("Name") or it.get("RulesetName")
                        if name: sample.append(name)

            evidence["rulesetCount"] = total
            evidence["sampleRulesets"] = sample

            passed = total >= 1
            evals.append(ServiceEvaluation(
                service="Glue",
                resource_id="account/region",
                evidence_path="Rulesets (count)",
                checked_field="rulesets count",
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
                reason=None if passed else "No Glue Data Quality rulesets",
                extract={
                    "code": self.code, "category":"5 (데이터 품질/출처/라인리지)", "service":"Glue Data Quality",
                    "console_path":"Glue → Data quality",
                    "check_how":"list-data-quality-rulesets >= 1",
                    "cli_cmd":"aws glue list-data-quality-rulesets",
                    "return_field":"Rulesets",
                    "compliant_value":">=1",
                    "non_compliant_value":"0",
                    "console_fix":"Data quality ruleset 생성",
                    "cli_fix_cmd":"aws glue create-data-quality-ruleset --name dq-rules --ruleset '{\"rules\":[{\"name\":\"no_nulls\",\"checkExpression\":\"col IS NOT NULL\"}]}'"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Glue", resource_id=None,
                    evidence_path="list-data-quality-rulesets",
                    checked_field="Rulesets",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
