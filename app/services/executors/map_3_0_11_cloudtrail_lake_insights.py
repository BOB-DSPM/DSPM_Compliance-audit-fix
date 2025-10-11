from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_11:
    code = "3.0-11"
    title = "CloudTrail Lake / Insights enabled"

    def audit(self) -> AuditResult:
        ct = boto3.client("cloudtrail")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"eventDataStores": 0, "insightsEnabledTrails": []}

        try:
            # 1) Lake: Event Data Stores 존재 여부
            try:
                # 일부 계정/리전에선 권한 또는 리전 미지원일 수 있음
                resp = ct.list_event_data_stores(MaxResults=50)
                eds = resp.get("EventDataStores", [])
                evidence["eventDataStores"] = len(eds)
            except ct.exceptions.InsufficientEncryptionPolicyException as _:
                eds = []
                evidence["eventDataStores"] = 0

            evals.append(ServiceEvaluation(
                service="CloudTrail",
                resource_id="account",
                evidence_path="EventDataStores[].(count)",
                checked_field="EventDataStores count",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["eventDataStores"],
                passed=(evidence["eventDataStores"] >= 1),
                decision=f"observed {evidence['eventDataStores']} >= 1 → "
                         f"{'passed' if evidence['eventDataStores'] >= 1 else 'failed'}",
                status="COMPLIANT" if evidence["eventDataStores"] >= 1 else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            # 2) Insights: 임의의 trail에 Insights 선택기 존재?
            trails = ct.describe_trails().get("trailList", [])
            insights_ok = False
            for t in trails:
                name = t.get("Name")
                try:
                    ins = ct.get_insight_selectors(TrailName=name)
                    sels = ins.get("InsightSelectors", [])
                    if sels:
                        insights_ok = True
                        evidence["insightsEnabledTrails"].append(name)
                except botocore.exceptions.ClientError:
                    pass

            evals.append(ServiceEvaluation(
                service="CloudTrail",
                resource_id="account",
                evidence_path="trail.InsightSelectors",
                checked_field="Insights enabled (any trail)",
                comparator="exists",
                expected_value=True,
                observed_value=bool(evidence["insightsEnabledTrails"]),
                passed=bool(evidence["insightsEnabledTrails"]),
                decision=("at least one trail has InsightSelectors → "
                          f"{'passed' if evidence['insightsEnabledTrails'] else 'failed'}"),
                status="COMPLIANT" if insights_ok else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"trails": evidence.get("insightsEnabledTrails")}
            ))

            status = "COMPLIANT" if (evidence["eventDataStores"] >= 1 and insights_ok) else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "CloudTrail",
                    "console_path": "CloudTrail → Lake/Insights",
                    "check_how": "Event Data Store 및 Insights 활성",
                    "cli_cmd": "aws cloudtrail list-event-data-stores; aws cloudtrail get-insight-selectors --trail-name TRAIL",
                    "return_field": "EventDataStores, InsightSelectors",
                    "compliant_value": "구성됨",
                    "non_compliant_value": "없음",
                    "console_fix": "콘솔에서 데이터 스토어/인사이트 활성화",
                    "cli_fix_cmd": "-"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudTrail", resource_id=None,
                    evidence_path="EventDataStores/InsightSelectors",
                    checked_field="Lake/Insights",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions", status="SKIPPED",
                    source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
