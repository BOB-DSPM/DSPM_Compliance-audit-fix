from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_11_0_01:
    """
    11.0-01 — AWS Organizations(OUs): dev/test/prod 등 최소 2개 OU 분리 확인
    - console: Organizations → OUs
    - check: list_roots → 각 Root의 OU 총합 >= 2
    - fix: OU 생성 후 계정 이동
    """
    code = "11.0-01"
    title = "Organizations OU separation (>=2)"

    def audit(self) -> AuditResult:
        org = boto3.client("organizations")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"rootsChecked": 0, "ouCountTotal": 0, "perRoot": []}

        try:
            roots = org.list_roots().get("Roots", [])
            for root in roots:
                root_id = root.get("Id")
                evidence["rootsChecked"] += 1

                # paginate OUs for this root
                ou_count = 0
                paginator = org.get_paginator("list_organizational_units_for_parent")
                for page in paginator.paginate(ParentId=root_id):
                    ou_count += len(page.get("OrganizationalUnits", []) or [])

                evidence["ouCountTotal"] += ou_count
                evidence["perRoot"].append({"rootId": root_id, "ouCount": ou_count})

            # 최종 판정: 전체 OU 수가 2개 이상이면 COMPLIANT
            passed = evidence["ouCountTotal"] >= 2
            status = "COMPLIANT" if passed else "NON_COMPLIANT"

            evals.append(ServiceEvaluation(
                service="AWS Organizations",
                resource_id="org-root(s)",
                evidence_path="Roots[].OrganizationalUnits[].(count)",
                checked_field="OU count total",
                comparator="ge",
                expected_value=2,
                observed_value=evidence["ouCountTotal"],
                passed=passed,
                decision=f"observed {evidence['ouCountTotal']} >= 2 → {'passed' if passed else 'failed'}",
                status=status,
                source="aws-sdk",
                extra={"perRoot": evidence["perRoot"][:3]}  # 미리보기 샘플
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "Fewer than 2 OUs",
                extract={
                    "code": self.code, "category": "11 (환경 분리/마스킹)", "service": "AWS Organizations",
                    "console_path": "Organizations → OUs",
                    "check_how": "Root별 OU 총합이 2개 이상인지",
                    "cli_cmd": "aws organizations list-organizational-units-for-parent --parent-id ROOT_ID",
                    "return_field": "OrganizationalUnits",
                    "compliant_value": "2개 이상",
                    "non_compliant_value": "1개 이하",
                    "console_fix": "OU 생성 후 계정 이동",
                    "cli_fix_cmd": "aws organizations create-organizational-unit --parent-id ROOT_ID --name Production"
                }
            )

        except botocore.exceptions.ClientError as e:
            # 예: AWS Organizations 비활성, 권한 부족 등
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="AWS Organizations",
                    resource_id=None,
                    evidence_path="Roots/OrganizationalUnits",
                    checked_field="OU count",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions or org not enabled",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions or Organizations not enabled",
                extract=None
            )
