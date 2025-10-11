from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_11_0_03:
    code = "11.0-03"
    title = "S3 Event Masking (Lambda notifications)"

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"bucketsChecked": 0, "withLambda": [], "withoutLambda": []}

        try:
            # 모든 버킷 순회 (조직/계정 정책에 따라 제한될 수 있음)
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b.get("Name")
                evidence["bucketsChecked"] += 1
                try:
                    cfg = s3.get_bucket_notification_configuration(Bucket=name)
                    lambdas = cfg.get("LambdaFunctionConfigurations", [])
                    has_lambda = len(lambdas) > 0
                    if has_lambda:
                        evidence["withLambda"].append(name)
                    else:
                        evidence["withoutLambda"].append(name)

                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="Bucket.Notification.LambdaFunctionConfigurations",
                        checked_field="LambdaFunctionConfigurations",
                        comparator="exists",
                        expected_value=True,
                        observed_value=has_lambda,
                        passed=has_lambda,
                        decision=("LambdaFunctionConfigurations exists → "
                                  f"{'passed' if has_lambda else 'failed'}"),
                        status="COMPLIANT" if has_lambda else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"lambdaConfigs": lambdas[:2]}  # 일부만 미리보기
                    ))
                except botocore.exceptions.ClientError as ie:
                    # 권한 없으면 해당 버킷은 스킵 판정으로 추가
                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="Bucket.Notification",
                        checked_field="LambdaFunctionConfigurations",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate this bucket: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            # 조직 정책상 특정 대상 버킷만 요구된다면, 나중에 필터를 넣어 좁히면 됨.
            compliant_any = len(evidence["withLambda"]) >= 1
            status = "SKIPPED" if evidence["bucketsChecked"] == 0 else ("COMPLIANT" if compliant_any else "NON_COMPLIANT")
            reason = None if status != "SKIPPED" else "No buckets found"

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=reason,
                extract={
                    "code": self.code, "category": "11 (환경 분리/마스킹)", "service": "S3",
                    "console_path": "S3 → Event notifications → Lambda",
                    "check_how": "Lambda 알림 구성 존재 여부",
                    "cli_cmd": "aws s3api get-bucket-notification-configuration --bucket BUCKET",
                    "return_field": "LambdaFunctionConfigurations",
                    "compliant_value": "존재",
                    "non_compliant_value": "없음",
                    "console_fix": "버킷 알림에 Lambda 연결(업로드시 마스킹/표준화 함수)",
                    "cli_fix_cmd": "aws s3api put-bucket-notification-configuration --bucket BUCKET --notification-configuration file://notif.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3", resource_id=None,
                    evidence_path="Buckets", checked_field="LambdaFunctionConfigurations",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
