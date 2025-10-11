from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_12:
    code = "2.0-12"
    title = "SNS"

    def audit(self) -> AuditResult:
        client = boto3.client("sns")
        evals: List[ServiceEvaluation] = []
        ev: Dict[str, Any] = {"topics": 0, "kms": 0, "noKms": []}

        try:
            arns = []
            paginator = client.get_paginator("list_topics")
            for page in paginator.paginate():
                arns.extend([t["TopicArn"] for t in page.get("Topics", [])])
            ev["topics"] = len(arns)

            for arn in arns:
                attrs = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                kms = attrs.get("KmsMasterKeyId")
                ok = bool(kms)
                if ok: ev["kms"] += 1
                else: ev["noKms"].append(arn)

                evals.append(ServiceEvaluation(
                    service="SNS", resource_id=arn, evidence_path="Attributes.KmsMasterKeyId",
                    checked_field="KmsMasterKeyId", comparator="exists", expected_value="exists",
                    observed_value=kms, passed=ok, decision="exists" if ok else "missing",
                    status="COMPLIANT" if ok else "NON_COMPLIANT", source="aws-sdk", extra={}
                ))

            final = "NON_COMPLIANT" if ev["noKms"] else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=final,
                evaluations=evals, evidence=ev, reason=None,
                extract={
                    "code": self.code, "category":"2 (암호화/KMS/TLS/At-rest)", "service":"SNS",
                    "console_path":"SNS → 토픽 → 암호화", "check_how":"KMS 키 연결",
                    "cli_cmd":"aws sns get-topic-attributes --topic-arn ARN",
                    "return_field":"KmsMasterKeyId", "compliant_value":"존재", "non_compliant_value":"없음",
                    "console_fix":"SNS → Server-side encryption 설정",
                    "cli_fix_cmd":"aws sns set-topic-attributes --topic-arn ARN --attribute-name KmsMasterKeyId --attribute-value KEY_ARN"
                }
            )
        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="SNS", resource_id=None, evidence_path="Attributes.KmsMasterKeyId",
                    checked_field="KMS", comparator="exists", expected_value="exists",
                    observed_value=None, passed=None, decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
