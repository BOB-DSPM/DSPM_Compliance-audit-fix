from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_03:
    code = "2.0-03"
    title = "DynamoDB"

    def audit(self) -> AuditResult:
        client = boto3.client("dynamodb")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"tables": 0, "enabled": 0, "disabled": []}

        try:
            tables = []
            paginator = client.get_paginator("list_tables")
            for page in paginator.paginate():
                tables.extend(page.get("TableNames", []))
            evidence["tables"] = len(tables)

            for t in tables:
                desc = client.describe_table(TableName=t)["Table"]
                sse = desc.get("SSEDescription", {})
                status = sse.get("Status")
                enabled = (status == "ENABLED")
                if enabled:
                    evidence["enabled"] += 1
                else:
                    evidence["disabled"].append(t)

                evals.append(ServiceEvaluation(
                    service="DynamoDB", resource_id=t,
                    evidence_path="Table.SSEDescription.Status",
                    checked_field="SSEDescription.Status",
                    comparator="eq", expected_value="ENABLED", observed_value=status,
                    passed=enabled, decision=f'observed "{status}" == "ENABLED" → {"passed" if enabled else "failed"}',
                    status="COMPLIANT" if enabled else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if evidence["disabled"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)","service":"DynamoDB",
                    "console_path":"DynamoDB → 테이블 → 암호화","check_how":"SSE 상태",
                    "cli_cmd":"aws dynamodb describe-table --table-name TBL --query \"Table.SSEDescription.Status\"",
                    "return_field":"SSEDescription.Status","compliant_value":"ENABLED","non_compliant_value":"DISABLED",
                    "console_fix":"DynamoDB → Manage encryption → KMS 키 선택",
                    "cli_fix_cmd":"aws dynamodb update-table --table-name TBL --sse-specification Enabled=true,SSEType=KMS"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="DynamoDB", resource_id=None,
                    evidence_path="Table.SSEDescription.Status", checked_field="SSE",
                    comparator="eq", expected_value="ENABLED", observed_value=None,
                    passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
