from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_4_0_03:
    code = "4.0-03"
    title = "DynamoDB TTL enabled"

    def audit(self) -> AuditResult:
        ddb = boto3.client("dynamodb")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"checkedTables": 0, "nonCompliant": []}

        try:
            paginator = ddb.get_paginator("list_tables")
            tables: List[str] = []
            for page in paginator.paginate():
                tables.extend(page.get("TableNames", []))

            evidence["checkedTables"] = len(tables)

            if not tables:
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="DynamoDB",
                        resource_id=None,
                        evidence_path="ListTables",
                        checked_field="TimeToLiveStatus",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="no tables → cannot evaluate",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={}
                    )],
                    evidence=evidence,
                    reason="No tables",
                    extract=_extract_meta(),
                )

            for t in tables:
                try:
                    ttl = ddb.describe_time_to_live(TableName=t)
                    status = ttl.get("TimeToLiveDescription", {}).get("TimeToLiveStatus", "DISABLED")
                    enabled = (status == "ENABLED")
                    if not enabled:
                        evidence["nonCompliant"].append(t)

                    evals.append(ServiceEvaluation(
                        service="DynamoDB",
                        resource_id=t,
                        evidence_path="TimeToLiveDescription.TimeToLiveStatus",
                        checked_field="TimeToLiveStatus",
                        comparator="eq",
                        expected_value="ENABLED",
                        observed_value=status,
                        passed=enabled,
                        decision=f"observed {status} == ENABLED → {'passed' if enabled else 'failed'}",
                        status="COMPLIANT" if enabled else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="DynamoDB",
                        resource_id=t,
                        evidence_path="DescribeTimeToLive",
                        checked_field="TimeToLiveStatus",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: error",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            overall = "COMPLIANT" if not evidence["nonCompliant"] else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall,
                evaluations=evals,
                evidence=evidence,
                reason=None if overall == "COMPLIANT" else "Tables without TTL enabled exist",
                extract=_extract_meta(),
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="DynamoDB",
                    resource_id=None,
                    evidence_path="ListTables",
                    checked_field="TimeToLiveStatus",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=_extract_meta(),
            )

def _extract_meta() -> Dict[str, Any]:
    return {
        "code": "4.0-03",
        "category": "4 (데이터 보존/파기/재식별)",
        "service": "DynamoDB",
        "console_path": "DynamoDB → 테이블 → TTL",
        "check_how": "TimeToLiveStatus == ENABLED",
        "cli_cmd": "aws dynamodb describe-time-to-live --table-name TBL",
        "return_field": "TimeToLiveDescription.TimeToLiveStatus",
        "compliant_value": "ENABLED",
        "non_compliant_value": "DISABLED",
        "console_fix": "테이블 TTL 기능 활성화",
        "cli_fix_cmd": 'aws dynamodb update-time-to-live --table-name TBL --time-to-live-specification "Enabled=true,AttributeName=expiresAt"'
    }
