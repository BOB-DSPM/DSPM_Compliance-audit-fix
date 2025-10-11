from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_02:
    code = "2.0-02"
    title = "RDS"

    def audit(self) -> AuditResult:
        client = boto3.client("rds")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"dbInstances": 0, "encrypted": 0, "nonEncrypted": []}

        try:
            paginator = client.get_paginator("describe_db_instances")
            dbs = []
            for page in paginator.paginate():
                dbs.extend(page.get("DBInstances", []))

            evidence["dbInstances"] = len(dbs)
            for db in dbs:
                rid = db["DBInstanceIdentifier"]
                enc = bool(db.get("StorageEncrypted"))
                passed = enc is True

                if not passed:
                    evidence["nonEncrypted"].append(rid)

                evals.append(ServiceEvaluation(
                    service="RDS",
                    resource_id=rid,
                    evidence_path="DBInstances[*].StorageEncrypted",
                    checked_field="StorageEncrypted",
                    comparator="eq",
                    expected_value=True,
                    observed_value=enc,
                    passed=passed,
                    decision=f"observed {enc} == True → {'passed' if passed else 'failed'}",
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))

            status = "NON_COMPLIANT" if evidence["nonEncrypted"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)","service":"RDS",
                    "console_path":"RDS → DB → 구성","check_how":"StorageEncrypted",
                    "cli_cmd":"aws rds describe-db-instances --query \"DBInstances[*].StorageEncrypted\"",
                    "return_field":"StorageEncrypted","compliant_value":"TRUE","non_compliant_value":"FALSE",
                    "console_fix":"RDS 스냅샷 암호화 복사 → 새 DB 복원",
                    "cli_fix_cmd":"aws rds copy-db-snapshot --source-db-snapshot-identifier SRC --target-db-snapshot-identifier TARGET --kms-key-id KEY"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="RDS", resource_id=None, evidence_path="DBInstances.StorageEncrypted",
                    checked_field="StorageEncrypted", comparator="eq", expected_value=True,
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
