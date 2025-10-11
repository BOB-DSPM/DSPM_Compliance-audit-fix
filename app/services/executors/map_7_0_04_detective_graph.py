from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_7_0_04:
    code = "7.0-04"
    title = "Detective graphs enabled"

    def audit(self) -> AuditResult:
        dtv = boto3.client("detective")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"graphs": 0}

        try:
            resp = dtv.list_graphs(MaxResults=50)
            graphs = resp.get("GraphList", [])
            evidence["graphs"] = len(graphs)

            evals.append(ServiceEvaluation(
                service="Detective",
                resource_id="account/region",
                evidence_path="GraphList[].(count)",
                checked_field="Graph count",
                comparator="ge",
                expected_value=1,
                observed_value=len(graphs),
                passed=(len(graphs) >= 1),
                decision=f"observed {len(graphs)} >= 1 → {'passed' if len(graphs) >= 1 else 'failed'}",
                status="COMPLIANT" if len(graphs) >= 1 else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            status = "COMPLIANT" if len(graphs) >= 1 else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category": "7 (모니터링/임계치/시간동기화)", "service": "Detective",
                    "console_path": "Detective → Graphs",
                    "check_how": "그래프 활성",
                    "cli_cmd": "aws detective list-graphs",
                    "return_field": "GraphList",
                    "compliant_value": ">=1",
                    "non_compliant_value": "없음",
                    "console_fix": "Enable Detective / 새 Graph",
                    "cli_fix_cmd": "aws detective create-graph"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Detective", resource_id=None,
                    evidence_path="GraphList", checked_field="count",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
