from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_6_0_01:
    code = "6.0-01"
    title = "SageMaker Endpoints 상태 (InService)"

    def audit(self) -> AuditResult:
        sm = boto3.client("sagemaker")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"endpointsChecked": 0, "nonInService": [], "errors": []}

        try:
            paginator = sm.get_paginator("list_endpoints")
            summaries = []
            for page in paginator.paginate():
                summaries.extend(page.get("Endpoints", []))
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="SageMaker", resource_id=None,
                    evidence_path="Endpoints", checked_field="EndpointStatus",
                    comparator="exists", expected_value=True, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions to list endpoints",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )

        for s in summaries:
            name = s.get("EndpointName")
            status = s.get("EndpointStatus")  # 보통 Summary에도 포함됨
            evidence["endpointsChecked"] += 1
            passed = (status == "InService")
            if not passed:
                evidence["nonInService"].append({"endpoint": name, "status": status})

            evals.append(ServiceEvaluation(
                service="SageMaker",
                resource_id=name,
                evidence_path="Endpoints[].EndpointStatus",
                checked_field="EndpointStatus",
                comparator="eq",
                expected_value="InService",
                observed_value=status,
                passed=passed,
                decision=f"observed {status} == InService → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

        if evidence["endpointsChecked"] == 0:
            overall = "SKIPPED"
            reason = "No endpoints"
        else:
            overall = "NON_COMPLIANT" if evidence["nonInService"] else "COMPLIANT"
            reason = None if overall != "NON_COMPLIANT" else "Endpoints not InService exist"

        return AuditResult(
            mapping_code=self.code, title=self.title, status=overall,
            evaluations=evals, evidence=evidence, reason=reason,
            extract={
                "code": self.code, "category": "6 (모델/배포 무결성)", "service": "SageMaker",
                "console_path": "SageMaker → Endpoints",
                "check_how": "EndpointStatus 가 InService",
                "cli_cmd": "aws sagemaker describe-endpoint --endpoint-name NAME",
                "return_field": "EndpointStatus",
                "compliant_value": "InService",
                "non_compliant_value": "Failed 등",
                "console_fix": "새 EndpointConfig로 업데이트/롤백",
                "cli_fix_cmd": "aws sagemaker update-endpoint --endpoint-name NAME --endpoint-config-name CFG"
            }
        )
