from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_5_0_04:
    code = "5.0-04"
    title = "SageMaker Feature Store 상태"

    def audit(self) -> AuditResult:
        sm = boto3.client("sagemaker")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"featureGroups": 0, "ok": 0, "failed": [], "sample": []}

        try:
            paginator = sm.get_paginator("list_feature_groups")
            fgs = []
            for page in paginator.paginate():
                fgs.extend(page.get("FeatureGroupSummaries", []) or [])

            evidence["featureGroups"] = len(fgs)
            for g in fgs:
                name = g.get("FeatureGroupName")
                status = g.get("FeatureGroupStatus")
                good = status in ("Created", "CreateComplete", "Active")
                if good:
                    evidence["ok"] += 1
                else:
                    evidence["failed"].append({"name": name, "status": status})

                evals.append(ServiceEvaluation(
                    service="SageMaker",
                    resource_id=name,
                    evidence_path="FeatureGroupSummaries[].FeatureGroupStatus",
                    checked_field="FeatureGroupStatus",
                    comparator="eq",
                    expected_value="Created/Active",
                    observed_value=status,
                    passed=good,
                    decision=f"observed {status} in [Created/Active] → {'passed' if good else 'failed'}",
                    status="COMPLIANT" if good else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            overall_pass = evidence["featureGroups"] > 0 and len(evidence["failed"]) == 0
            overall_status = "COMPLIANT" if overall_pass else ("NON_COMPLIANT" if evidence["featureGroups"] > 0 else "NON_COMPLIANT")

            return AuditResult(
                mapping_code=self.code, title=self.title, status=overall_status,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category":"5 (데이터 품질/출처/라인리지)", "service":"SageMaker",
                    "console_path":"SageMaker → Feature Store",
                    "check_how":"FeatureGroupStatus == Created/Active",
                    "cli_cmd":"aws sagemaker list-feature-groups",
                    "return_field":"FeatureGroupSummaries[].FeatureGroupStatus",
                    "compliant_value":"Created/Active", "non_compliant_value":"Failed",
                    "console_fix":"스키마/권한/스토어 구성을 점검 후 재생성/정상화",
                    "cli_fix_cmd":"aws sagemaker create-feature-group --feature-group-name fg --record-identifiers-value-column-name id --event-time-feature-name ts --offline-store-config file://cfg.json"
                }
            )
        except botocore.exceptions.ClientError as e:
            evals.append(ServiceEvaluation(
                service="SageMaker", resource_id=None, evidence_path="FeatureGroupSummaries",
                checked_field="FeatureGroupStatus", comparator="eq", expected_value="Created/Active",
                observed_value=None, passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, title=self.title, status="SKIPPED",
                               evaluations=evals, evidence={}, reason="Missing permissions or API error", extract=None)
