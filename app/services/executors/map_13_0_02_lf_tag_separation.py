# app/services/executors/map_13_0_02_lf_tag_separation.py
from __future__ import annotations
from typing import List, Dict, Any, Optional
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_13_0_02:
    code = "13.0-02"
    title = "Lake Formation LF-Tag-based separation"

    def audit(self) -> AuditResult:
        lf = boto3.client("lakeformation")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"lfTagPolicyPermissions": 0, "sample": []}

        try:
            # ⬇️ paginator 대신 수동 NextToken 루프 사용
            perms: List[Dict[str, Any]] = []
            token: Optional[str] = None
            while True:
                kwargs = {"ResourceType": "LF_TAG_POLICY"}
                if token:
                    kwargs["NextToken"] = token
                resp = lf.list_permissions(**kwargs)
                perms.extend(resp.get("PrincipalResourcePermissions", []) or [])
                token = resp.get("NextToken")
                if not token:
                    break

            evidence["lfTagPolicyPermissions"] = len(perms)
            for p in perms[:2]:  # 샘플만 첨부
                evidence["sample"].append({
                    "principal": p.get("Principal", {}),
                    "resource": p.get("Resource", {}),
                    "permissions": p.get("Permissions", [])
                })

            passed = evidence["lfTagPolicyPermissions"] >= 1
            status = "COMPLIANT" if passed else "NON_COMPLIANT"

            evals.append(ServiceEvaluation(
                service="Lake Formation",
                resource_id="account",
                evidence_path="PrincipalResourcePermissions(ResourceType=LF_TAG_POLICY)",
                checked_field="LF_TAG_POLICY permission count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["lfTagPolicyPermissions"],
                passed=passed,
                decision=f"observed {evidence['lfTagPolicyPermissions']} >= 1 → {'passed' if passed else 'failed'}",
                status=status,
                source="aws-sdk",
                extra={"sample": evidence["sample"]}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "No LF-Tag policy-based permissions found",
                extract={
                    "code": self.code, "category": "13 (멀티테넌시 격리)", "service": "Lake Formation",
                    "console_path": "Lake Formation → Permissions",
                    "check_how": "LF-Tag Policy 기반 권한 존재 여부",
                    "cli_cmd": "aws lakeformation list-permissions --resource-type LF_TAG_POLICY",
                    "return_field": "PrincipalResourcePermissions",
                    "compliant_value": ">= 1", "non_compliant_value": "0",
                    "console_fix": "LF-Tag 생성 후, LF-Tag Policy로 테넌트 별 권한 부여",
                    "cli_fix_cmd": (
                        "aws lakeformation create-lf-tag --tag-key purpose --tag-values pii && "
                        "aws lakeformation grant-permissions --principal DataLakePrincipalIdentifier=ARN "
                        "--resource file://res.json --permissions SELECT"
                    ),
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Lake Formation",
                    resource_id=None,
                    evidence_path="PrincipalResourcePermissions",
                    checked_field="LF_TAG_POLICY",
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
