# app/services/executors/map_5_0_05_lakeformation_lftags.py
from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_05:
    code = "5.0-05"
    title = "Lake Formation LF-Tags"

    def audit(self) -> AuditResult:
        lf = boto3.client("lakeformation")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"lfTagsCount": 0, "sampleTags": []}

        try:
            # list-lf-tags는 페이지네이션(NextToken) 지원
            total = 0
            next_token = None
            samples = []
            while True:
                params = {}
                if next_token:
                    params["NextToken"] = next_token
                resp = lf.list_lf_tags(**params)
                tags = resp.get("LFTags", []) or []
                total += len(tags)
                if len(samples) < 5:
                    for t in tags:
                        if len(samples) >= 5:
                            break
                        samples.append({"TagKey": t.get("TagKey"), "TagValues": t.get("TagValues", [])})
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            evidence["lfTagsCount"] = total
            evidence["sampleTags"] = samples

            passed = total >= 1
            evals.append(ServiceEvaluation(
                service="Lake Formation",
                resource_id="account/region",
                evidence_path="LFTags",
                checked_field="LF-Tag count",
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
                mapping_code=self.code,
                title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "No LF-Tags found",
                extract={
                    "code": self.code,
                    "category": "5 (데이터 품질/출처/라인리지)",
                    "service": "Lake Formation",
                    "console_path": "Lake Formation → LF-Tags",
                    "check_how": "list-lf-tags",
                    "cli_cmd": "aws lakeformation list-lf-tags",
                    "return_field": "LFTags",
                    "compliant_value": "존재",
                    "non_compliant_value": "없음",
                    "console_fix": "LF-Tag 생성 후 리소스에 부여",
                    "cli_fix_cmd": "aws lakeformation create-lf-tag --tag-key purpose --tag-values pii"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Lake Formation",
                    resource_id=None,
                    evidence_path="LFTags",
                    checked_field="list-lf-tags",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=None
            )
