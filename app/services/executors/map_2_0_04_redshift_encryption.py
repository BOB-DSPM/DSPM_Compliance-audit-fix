from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_04:
    code = "2.0-04"
    title = "Redshift"

    def audit(self) -> AuditResult:
        client = boto3.client("redshift")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"clusters": 0, "encrypted": 0, "nonEncrypted": []}

        try:
            clusters = client.describe_clusters().get("Clusters", [])
            ev["clusters"] = len(clusters)
            for c in clusters:
                cid = c["ClusterIdentifier"]
                enc = bool(c.get("Encrypted"))
                if enc: ev["encrypted"] += 1
                else: ev["nonEncrypted"].append(cid)

                evals.append(ServiceEvaluation(
                    service="Redshift", resource_id=cid,
                    evidence_path="Clusters[*].Encrypted",
                    checked_field="Encrypted", comparator="eq", expected_value=True,
                    observed_value=enc, passed=enc,
                    decision=f"observed {enc} == True → {'passed' if enc else 'failed'}",
                    status="COMPLIANT" if enc else "NON_COMPLIANT",
                    source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["nonEncrypted"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"Redshift",
                    "console_path":"Redshift → 클러스터 → 구성","check_how":"At-rest KMS 암호화",
                    "cli_cmd":"aws redshift describe-clusters --query \"Clusters[*].Encrypted\"",
                    "return_field":"Encrypted","compliant_value":"TRUE","non_compliant_value":"FALSE",
                    "console_fix":"암호화 스냅샷 생성 → 새 클러스터 복원",
                    "cli_fix_cmd":"aws redshift create-cluster-snapshot --cluster-identifier CL --snapshot-identifier ID && aws redshift restore-from-cluster-snapshot --cluster-identifier NEW --snapshot-identifier ID --kms-key-id KEY"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Redshift", resource_id=None, evidence_path="Clusters.Encrypted",
                    checked_field="Encrypted", comparator="eq", expected_value=True,
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
