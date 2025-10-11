from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_9_0_01:
    code = "9.0-01"
    title = "DynamoDB PITR 활성화"

    def audit(self) -> AuditResult:
        ddb = boto3.client("dynamodb")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"tables": 0, "enabled": 0, "disabled": []}

        try:
            # 모든 테이블 순회
            paginator = ddb.get_paginator("list_tables")
            tables = []
            for page in paginator.paginate():
                tables.extend(page.get("TableNames", []) or [])
            evidence["tables"] = len(tables)

            if not tables:
                return AuditResult(
                    mapping_code=self.code, title=self.title, status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="DynamoDB", resource_id=None,
                        evidence_path="Tables", checked_field="TimeToLive / PITR",
                        comparator="exists", expected_value=True,
                        observed_value=False, passed=None,
                        decision="no tables → cannot evaluate", status="SKIPPED",
                        source="aws-sdk", extra={}
                    )],
                    evidence=evidence, reason="No tables", extract=None
                )

            for t in tables:
                try:
                    resp = ddb.describe_continuous_backups(TableName=t)
                    status = ((resp.get("ContinuousBackupsDescription") or {})
                              .get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus")
                    enabled = (status == "ENABLED")
                    if enabled:
                        evidence["enabled"] += 1
                    else:
                        evidence["disabled"].append(t)

                    evals.append(ServiceEvaluation(
                        service="DynamoDB", resource_id=t,
                        evidence_path="ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus",
                        checked_field="PITR Status",
                        comparator="eq", expected_value="ENABLED",
                        observed_value=status, passed=enabled,
                        decision=f"observed {status} == ENABLED → {'passed' if enabled else 'failed'}",
                        status="COMPLIANT" if enabled else "NON_COMPLIANT",
                        source="aws-sdk", extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="DynamoDB", resource_id=t,
                        evidence_path="describe_continuous_backups",
                        checked_field="PITR Status",
                        comparator="eq", expected_value="ENABLED",
                        observed_value=None, passed=None,
                        decision="cannot evaluate this table: missing permissions",
                        status="SKIPPED", source="aws-sdk", extra={"error": str(ie)}
                    ))

            overall = "COMPLIANT" if evidence["tables"] > 0 and len(evidence["disabled"]) == 0 else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=overall,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category": "9 (백업/복구/DR)", "service": "DynamoDB",
                    "console_path": "DynamoDB → Backups",
                    "check_how": "describe-continuous-backups → PointInTimeRecoveryStatus",
                    "cli_cmd": "aws dynamodb describe-continuous-backups --table-name TBL",
                    "return_field": "ContinuousBackupsStatus/PointInTimeRecoveryStatus",
                    "compliant_value": "ENABLED", "non_compliant_value": "DISABLED",
                    "console_fix": "테이블 설정에서 Point-in-time recovery 활성화",
                    "cli_fix_cmd": "aws dynamodb update-continuous-backups --table-name TBL --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
                }
            )
        except botocore.exceptions.ClientError as e:
            evals.append(ServiceEvaluation(
                service="DynamoDB", resource_id=None, evidence_path="list_tables",
                checked_field="Tables", comparator="exists", expected_value=True,
                observed_value=None, passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, title=self.title, status="SKIPPED",
                               evaluations=evals, evidence={}, reason="Missing permissions or API error", extract=None)
