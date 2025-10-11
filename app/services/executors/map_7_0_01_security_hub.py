from __future__ import annotations
from typing import List, Dict, Any, Optional
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_7_0_01:
    code = "7.0-01"
    title = "Security Hub standards enabled"

    def audit(self) -> AuditResult:
        sh = boto3.client("securityhub")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "securityHubEnabled": False,
            "enabledStandardsCount": 0,
            "sampleStandardSubs": []
        }

        # 1) Security Hub 구독 여부
        try:
            # 구독되어 있으면 HubArn이 내려옴. 미구독이면 예외 발생
            hub = sh.describe_hub()
            evidence["securityHubEnabled"] = bool(hub.get("HubArn"))
            evals.append(ServiceEvaluation(
                service="Security Hub",
                resource_id=hub.get("HubArn", "account"),
                evidence_path="DescribeHub.HubArn",
                checked_field="Hub enabled",
                comparator="exists",
                expected_value=True,
                observed_value=evidence["securityHubEnabled"],
                passed=evidence["securityHubEnabled"],
                decision=("HubArn exists → passed"
                          if evidence["securityHubEnabled"] else "HubArn missing → failed"),
                status="COMPLIANT" if evidence["securityHubEnabled"] else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))
        except botocore.exceptions.ClientError as e:
            # 권한 부족 등은 SKIPPED
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Security Hub",
                    resource_id=None,
                    evidence_path="DescribeHub",
                    checked_field="Hub enabled",
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

        # 2) 활성화된 표준 개수 (>=1 권장)
        if evidence["securityHubEnabled"]:
            try:
                # paginator 지원됨
                subs = []
                paginator = sh.get_paginator("get_enabled_standards")
                for page in paginator.paginate():
                    subs.extend(page.get("StandardsSubscriptions", []) or [])
                evidence["enabledStandardsCount"] = len(subs)
                evidence["sampleStandardSubs"] = [
                    {
                        "StandardsArn": s.get("StandardsArn"),
                        "StandardsStatus": s.get("StandardsStatus")
                    } for s in subs[:2]
                ]

                passed = evidence["enabledStandardsCount"] >= 1
                evals.append(ServiceEvaluation(
                    service="Security Hub",
                    resource_id="account",
                    evidence_path="StandardsSubscriptions(count)",
                    checked_field="Enabled standards count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=evidence["enabledStandardsCount"],
                    passed=passed,
                    decision=f"observed {evidence['enabledStandardsCount']} >= 1 → "
                             f"{'passed' if passed else 'failed'}",
                    status="COMPLIANT" if passed else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"sample": evidence["sampleStandardSubs"]}
                ))
            except botocore.exceptions.ClientError as e:
                evals.append(ServiceEvaluation(
                    service="Security Hub",
                    resource_id="account",
                    evidence_path="GetEnabledStandards",
                    checked_field="Enabled standards",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate enabled standards: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                ))

        # 최종 상태: 표준이 1개 이상이면 COMPLIANT, 아니면 NON_COMPLIANT
        # (Hub 자체가 꺼져 있으면 위 평가에서 이미 NON_COMPLIANT가 하나 생김)
        has_non = any(e.status == "NON_COMPLIANT" for e in evals)
        has_err  = any(e.status == "ERROR" for e in evals)
        status = "ERROR" if has_err else ("NON_COMPLIANT" if has_non else "COMPLIANT")

        return AuditResult(
            mapping_code=self.code,
            title=self.title,
            status=status,
            evaluations=evals,
            evidence=evidence,
            reason=None if status == "COMPLIANT" else (
                "Security Hub disabled" if not evidence["securityHubEnabled"]
                else "No standards enabled"
            ),
            extract={
                "code": self.code,
                "category": "7 (모니터링/임계치/시간동기화)",
                "service": "Security Hub",
                "console_path": "Security Hub → Findings / Standards",
                "check_how": "Hub 활성 및 Standards 구독 수",
                "cli_cmd": "aws securityhub describe-hub && aws securityhub get-enabled-standards",
                "return_field": "HubArn, StandardsSubscriptions[].StandardsStatus",
                "compliant_value": "Hub 활성 & 표준 ≥ 1",
                "non_compliant_value": "Hub 비활성 또는 표준 0",
                "console_fix": "Security Hub 활성화 후 원하는 표준(CIS, Foundational 등) 구독",
                "cli_fix_cmd": "aws securityhub enable-security-hub"
            }
        )
