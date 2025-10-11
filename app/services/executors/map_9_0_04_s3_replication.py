from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_9_0_04:
    code = "9.0-04"
    title = "S3 Replication (교차 리전/계정 복제 규칙)"

    def audit(self) -> AuditResult:
        s3 = boto3.client("s3")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "bucketsChecked": 0,
            "withReplication": [],
            "withoutReplication": [],
            "errors": [],
        }

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except botocore.exceptions.ClientError as e:
            # 계정 전체 버킷 조회 권한이 없을 때
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="S3",
                    resource_id=None,
                    evidence_path="Buckets",
                    checked_field="list_buckets",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions to list buckets",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                )],
                evidence={},
                reason="Missing permissions",
                extract=None,
            )

        for b in buckets:
            name = b.get("Name")
            evidence["bucketsChecked"] += 1
            try:
                # 존재하면 ReplicationConfiguration 키가 내려옴
                _ = s3.get_bucket_replication(Bucket=name)
                has_replication = True
            except botocore.exceptions.ClientError as ce:
                err_code = ce.response.get("Error", {}).get("Code")
                if err_code in ("ReplicationConfigurationNotFoundError", "NoSuchReplicationConfiguration"):
                    has_replication = False  # 규칙 미설정 → 미준수
                elif err_code in ("AccessDenied", "AllAccessDisabled"):
                    # 권한 없으면 해당 버킷은 SKIPPED로 처리
                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="Bucket.ReplicationConfiguration",
                        checked_field="ReplicationConfiguration",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate this bucket: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ce)},
                    ))
                    evidence["errors"].append({"bucket": name, "error": err_code})
                    continue
                else:
                    # 기타 오류도 스킵
                    evals.append(ServiceEvaluation(
                        service="S3",
                        resource_id=name,
                        evidence_path="Bucket.ReplicationConfiguration",
                        checked_field="ReplicationConfiguration",
                        comparator="exists",
                        expected_value=True,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate this bucket: unexpected error",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ce)},
                    ))
                    evidence["errors"].append({"bucket": name, "error": err_code})
                    continue

            if has_replication:
                evidence["withReplication"].append(name)
            else:
                evidence["withoutReplication"].append(name)

            evals.append(ServiceEvaluation(
                service="S3",
                resource_id=name,
                evidence_path="Bucket.ReplicationConfiguration",
                checked_field="ReplicationConfiguration",
                comparator="exists",
                expected_value=True,
                observed_value=has_replication,
                passed=has_replication,
                decision=("ReplicationConfiguration exists → "
                          f"{'passed' if has_replication else 'failed'}"),
                status="COMPLIANT" if has_replication else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

        # 전체 상태: 하나라도 미설정 버킷이 있으면 NON_COMPLIANT
        if evidence["bucketsChecked"] == 0:
            overall = "SKIPPED"
            reason = "No buckets found"
        else:
            overall = "NON_COMPLIANT" if evidence["withoutReplication"] else "COMPLIANT"
            reason = "Buckets without replication rules exist" if overall == "NON_COMPLIANT" else None

        return AuditResult(
            mapping_code=self.code,
            title=self.title,
            status=overall,
            evaluations=evals,
            evidence=evidence,
            reason=reason,
            extract={
                "code": self.code,
                "category": "9 (백업/복구/DR)",
                "service": "S3",
                "console_path": "S3 → Management → Replication",
                "check_how": "버킷 ReplicationConfiguration 존재 여부",
                "cli_cmd": "aws s3api get-bucket-replication --bucket BUCKET",
                "return_field": "ReplicationConfiguration",
                "compliant_value": "존재",
                "non_compliant_value": "없음",
                "console_fix": "버킷의 Management → Replication에서 규칙 생성(대상 리전/계정 및 역할 설정)",
                "cli_fix_cmd": "aws s3api put-bucket-replication --bucket BUCKET --replication-configuration file://replication.json",
            }
        )
