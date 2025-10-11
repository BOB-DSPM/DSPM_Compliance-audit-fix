from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_10:
    code = "2.0-10"
    title = "Kinesis Data Streams"

    def audit(self) -> AuditResult:
        client = boto3.client("kinesis")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"streams": 0, "kms": 0, "none": []}
        try:
            streams = client.list_streams().get("StreamNames", [])
            ev["streams"] = len(streams)
            for s in streams:
                summ = client.describe_stream_summary(StreamName=s)["StreamDescriptionSummary"]
                etype = summ.get("EncryptionType")
                ok = (etype == "KMS")
                if ok: ev["kms"] += 1
                else: ev["none"].append(s)

                evals.append(ServiceEvaluation(
                    service="Kinesis", resource_id=s, evidence_path="StreamDescriptionSummary.EncryptionType",
                    checked_field="EncryptionType", comparator="eq", expected_value="KMS",
                    observed_value=etype, passed=ok, decision=f'observed "{etype}" == "KMS" → {"passed" if ok else "failed"}',
                    status="COMPLIANT" if ok else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["none"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"Kinesis",
                    "console_path":"Kinesis → Streams → 설정", "check_how":"SSE-KMS 사용",
                    "cli_cmd":"aws kinesis describe-stream-summary --stream-name NAME --query \"StreamDescriptionSummary.EncryptionType\"",
                    "return_field":"StreamDescriptionSummary.EncryptionType",
                    "compliant_value":"KMS", "non_compliant_value":"NONE",
                    "console_fix":"Kinesis → Edit → Encryption KMS 설정",
                    "cli_fix_cmd":"aws kinesis start-stream-encryption --stream-name NAME --encryption-type KMS --key-id KEY"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Kinesis", resource_id=None, evidence_path="StreamDescriptionSummary.EncryptionType",
                    checked_field="EncryptionType", comparator="eq", expected_value="KMS",
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
