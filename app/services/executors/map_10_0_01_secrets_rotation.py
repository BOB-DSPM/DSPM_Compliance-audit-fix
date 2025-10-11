from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_10_0_01:
    """
    10.0-01 — Secrets Manager rotation enabled
    기준: 모든 사용자 Secrets에 대해 RotationEnabled=True
    """
    code = "10.0-01"
    title = "Secrets Manager rotation enabled"

    def audit(self) -> AuditResult:
        sm = boto3.client("secretsmanager")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "totalSecrets": 0,
            "rotated": 0,
            "notRotated": 0,
            "nonCompliantSecrets": [],   # 최대 10개 샘플
        }

        try:
            # 목록 페이지네이션
            next_token = None
            secrets: List[Dict[str, Any]] = []
            while True:
                params = {"MaxResults": 100}
                if next_token:
                    params["NextToken"] = next_token
                resp = sm.list_secrets(**params)
                secrets.extend(resp.get("SecretList", []) or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            evidence["totalSecrets"] = len(secrets)

            if evidence["totalSecrets"] == 0:
                # 시크릿이 없으면 SKIPPED
                return AuditResult(
                    mapping_code=self.code, title=self.title, status="SKIPPED",
                    evaluations=[ServiceEvaluation(
                        service="Secrets Manager",
                        resource_id=None,
                        evidence_path="SecretList(count)",
                        checked_field="totalSecrets",
                        comparator="ge",
                        expected_value=1,
                        observed_value=0,
                        passed=False,
                        decision="no secrets → cannot evaluate rotation",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={}
                    )],
                    evidence=evidence,
                    reason="No secrets found",
                    extract={
                        "code": self.code,
                        "category": "10 (비밀/자격증명 관리)",
                        "service": "Secrets Manager",
                        "console_path": "Secrets → Rotation",
                        "check_how": "각 Secret의 RotationEnabled 확인",
                        "cli_cmd": "aws secretsmanager describe-secret --secret-id ID --query RotationEnabled",
                        "return_field": "RotationEnabled",
                        "compliant_value": "TRUE",
                        "non_compliant_value": "FALSE",
                        "console_fix": "해당 Secret에서 Rotation 활성화 후 Lambda 로테이터 지정",
                        "cli_fix_cmd": "aws secretsmanager rotate-secret --secret-id ID"
                    }
                )

            # 각 시크릿 점검 (list_secrets에도 RotationEnabled가 보통 포함되지만, 정확성 위해 보강)
            for s in secrets:
                sid = s.get("ARN") or s.get("Name")
                name = s.get("Name")
                try:
                    d = sm.describe_secret(SecretId=sid)
                    rotated = bool(d.get("RotationEnabled"))
                    if rotated:
                        evidence["rotated"] += 1
                    else:
                        evidence["notRotated"] += 1
                        if len(evidence["nonCompliantSecrets"]) < 10:
                            evidence["nonCompliantSecrets"].append(name or sid)

                    evals.append(ServiceEvaluation(
                        service="Secrets Manager",
                        resource_id=name or sid,
                        evidence_path="DescribeSecret.RotationEnabled",
                        checked_field="RotationEnabled",
                        comparator="eq",
                        expected_value=True,
                        observed_value=rotated,
                        passed=rotated,
                        decision=f"observed {rotated} == True → {'passed' if rotated else 'failed'}",
                        status="COMPLIANT" if rotated else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="Secrets Manager",
                        resource_id=name or sid,
                        evidence_path="DescribeSecret",
                        checked_field="RotationEnabled",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate this secret: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            overall_compliant = (evidence["notRotated"] == 0)
            status = "COMPLIANT" if overall_compliant else "NON_COMPLIANT"
            reason = None if overall_compliant else "Secrets without rotation enabled exist"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=reason,
                extract={
                    "code": self.code,
                    "category": "10 (비밀/자격증명 관리)",
                    "service": "Secrets Manager",
                    "console_path": "Secrets → Rotation",
                    "check_how": "각 Secret의 RotationEnabled 확인",
                    "cli_cmd": "aws secretsmanager describe-secret --secret-id ID --query RotationEnabled",
                    "return_field": "RotationEnabled",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "해당 Secret에서 Rotation 활성화 후 Lambda 로테이터 지정",
                    "cli_fix_cmd": "aws secretsmanager rotate-secret --secret-id ID"
                }
            )

        except botocore.exceptions.ClientError as e:
            # 서비스 전체 접근 권한 부족/비활성 시
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Secrets Manager",
                    resource_id=None,
                    evidence_path="list_secrets/describe_secret",
                    checked_field="RotationEnabled",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions",
                extract=None
            )
