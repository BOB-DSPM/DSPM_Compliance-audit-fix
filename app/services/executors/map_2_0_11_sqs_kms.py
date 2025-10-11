from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_11:
    code = "2.0-11"
    title = "SQS"

    def audit(self) -> AuditResult:
        client = boto3.client("sqs")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"queues": 0, "kms": 0, "noKms": []}

        try:
            # 지역 기본 계정의 큐 URL 목록
            urls = client.list_queues().get("QueueUrls", [])
            ev["queues"] = len(urls)

            for url in urls:
                attrs = client.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId"]).get("Attributes", {})
                kms = attrs.get("KmsMasterKeyId")
                ok = bool(kms)
                if ok: ev["kms"] += 1
                else: ev["noKms"].append(url)

                evals.append(ServiceEvaluation(
                    service="SQS", resource_id=url,
                    evidence_path="Attributes.KmsMasterKeyId",
                    checked_field="KmsMasterKeyId",
                    comparator="exists", expected_value="exists", observed_value=kms,
                    passed=ok, decision="exists" if ok else "missing",
                    status="COMPLIANT" if ok else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["noKms"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"SQS",
                    "console_path":"SQS → 큐 → 암호화", "check_how":"KMS 키 연결",
                    "cli_cmd":"aws sqs get-queue-attributes --queue-url URL --attribute-names KmsMasterKeyId",
                    "return_field":"KmsMasterKeyId", "compliant_value":"존재", "non_compliant_value":"없음",
                    "console_fix":"SQS → Queue encryption 설정",
                    "cli_fix_cmd":"aws sqs set-queue-attributes --queue-url URL --attributes KmsMasterKeyId=KEY_ARN"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="SQS", resource_id=None, evidence_path="Attributes.KmsMasterKeyId",
                    checked_field="KMS", comparator="exists", expected_value="exists",
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
