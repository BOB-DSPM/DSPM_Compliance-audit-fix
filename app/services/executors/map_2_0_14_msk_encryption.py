from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_14:
    code = "2.0-14"
    title = "MSK (Kafka)"

    def audit(self) -> AuditResult:
        client = boto3.client("kafka")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"clusters": 0, "ok": 0, "notOk": []}
        try:
            arns = client.list_clusters().get("ClusterInfoList", [])
            ev["clusters"] = len(arns)
            for info in arns:
                arn = info["ClusterArn"]
                desc = client.describe_cluster(ClusterArn=arn)["ClusterInfo"]
                enc = desc.get("EncryptionInfo", {})
                at_rest = enc.get("EncryptionAtRest", {}).get("DataVolumeKMSKeyId")
                in_transit = enc.get("EncryptionInTransit", {})
                # 기준: at-rest KMS 존재 & client/broker TLS
                tls_ok = in_transit.get("ClientBroker") in ("TLS", "TLS_PLAINTEXT") and in_transit.get("InCluster", False)
                ok = (bool(at_rest) and tls_ok)

                if ok: ev["ok"] += 1
                else: ev["notOk"].append(arn)

                evals.append(ServiceEvaluation(
                    service="MSK", resource_id=arn,
                    evidence_path="ClusterInfo.EncryptionInfo",
                    checked_field="At-rest/Transit encryption",
                    comparator="custom", expected_value="KMS at-rest & TLS transit",
                    observed_value={"atRestKMS": bool(at_rest), "inTransit": in_transit},
                    passed=ok, decision="configured" if ok else "missing",
                    status="COMPLIANT" if ok else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["notOk"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"MSK(Kafka)",
                    "console_path":"MSK → Cluster → Security","check_how":"At-rest/전송 암호화, 클라이언트 인증",
                    "cli_cmd":"aws kafka describe-cluster --cluster-arn ARN --query \"ClusterInfo.EncryptionInfo\"",
                    "return_field":"ClusterInfo.EncryptionInfo", "compliant_value":"설정됨", "non_compliant_value":"미설정",
                    "console_fix":"클러스터 보안 설정 점검/재배포","cli_fix_cmd":"-"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="MSK", resource_id=None, evidence_path="ClusterInfo.EncryptionInfo",
                    checked_field="Encryption", comparator="custom", expected_value="configured",
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
