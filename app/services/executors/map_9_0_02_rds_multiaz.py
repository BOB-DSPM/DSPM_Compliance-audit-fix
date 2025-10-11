from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_9_0_02:
    code = "9.0-02"
    title = "RDS Multi-AZ 구성"

    def audit(self) -> AuditResult:
        rds = boto3.client("rds")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"dbInstances": 0, "multiAZ": 0, "nonMultiAZ": []}

        try:
            paginator = rds.get_paginator("describe_db_instances")
            dbs = []
            for page in paginator.paginate():
                dbs.extend(page.get("DBInstances", []) or [])
            evidence["dbInstances"] = len(dbs)

            if not dbs:
                return AuditResult(
                    mapping_code=self.code, title=self.title, status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="RDS", resource_id=None, evidence_path="DBInstances",
                        checked_field="MultiAZ", comparator="eq", expected_value=True,
                        observed_value=None, passed=None,
                        decision="no DB instances → cannot evaluate", status="SKIPPED",
                        source="aws-sdk", extra={}
                    )],
                    evidence=evidence, reason="No DB instances", extract=None
                )

            for db in dbs:
                rid = db.get("DBInstanceIdentifier")
                mz = bool(db.get("MultiAZ"))
                if mz:
                    evidence["multiAZ"] += 1
                else:
                    evidence["nonMultiAZ"].append(rid)

                evals.append(ServiceEvaluation(
                    service="RDS", resource_id=rid, evidence_path="DBInstances[*].MultiAZ",
                    checked_field="MultiAZ", comparator="eq", expected_value=True,
                    observed_value=mz, passed=mz,
                    decision=f"observed {mz} == True → {'passed' if mz else 'failed'}",
                    status="COMPLIANT" if mz else "NON_COMPLIANT",
                    source="aws-sdk", extra={}
                ))

            overall = "COMPLIANT" if evidence["dbInstances"] > 0 and len(evidence["nonMultiAZ"]) == 0 \
                      else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=overall,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category":"9 (백업/복구/DR)", "service":"RDS",
                    "console_path":"RDS → 인스턴스",
                    "check_how":"DBInstances[*].MultiAZ",
                    "cli_cmd":"aws rds describe-db-instances --query \"DBInstances[*].MultiAZ\"",
                    "return_field":"MultiAZ",
                    "compliant_value":"TRUE", "non_compliant_value":"FALSE",
                    "console_fix":"DB 인스턴스 수정에서 Multi-AZ 체크",
                    "cli_fix_cmd":"aws rds modify-db-instance --db-instance-identifier DB --multi-az --apply-immediately"
                }
            )
        except botocore.exceptions.ClientError as e:
            evals.append(ServiceEvaluation(
                service="RDS", resource_id=None, evidence_path="DBInstances",
                checked_field="MultiAZ", comparator="eq", expected_value=True,
                observed_value=None, passed=None,
                decision="cannot evaluate: missing permissions or error",
                status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, title=self.title, status="SKIPPED",
                               evaluations=evals, evidence={}, reason="Missing permissions or API error", extract=None)
