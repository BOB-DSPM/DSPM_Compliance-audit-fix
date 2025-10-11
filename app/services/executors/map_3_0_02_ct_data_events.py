from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_02:
    code = "3.0-02"
    title = "CloudTrail data events for S3/Lambda"

    def audit(self) -> AuditResult:
        ct = boto3.client("cloudtrail")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "trailsChecked": 0,
            "withDataEvents": [],
            "withoutDataEvents": []
        }

        try:
            trails = ct.describe_trails().get("trailList", []) or []
            if not trails:
                # 트레일 자체가 없으면 비준수
                evals.append(ServiceEvaluation(
                    service="CloudTrail",
                    resource_id="account",
                    evidence_path="describe_trails.trailList",
                    checked_field="trails count",
                    comparator="ge",
                    expected_value=1,
                    observed_value=0,
                    passed=False,
                    decision="observed 0 >= 1 → failed",
                    status="NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                return AuditResult(
                    mapping_code=self.code, title=self.title, status="NON_COMPLIANT",
                    evaluations=evals, evidence=evidence,
                    reason="No CloudTrail trails configured",
                    extract={
                        "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "CloudTrail",
                        "console_path": "CloudTrail → Trails → Event selectors",
                        "check_how": "Data events for S3/Lambda 존재 여부",
                        "cli_cmd": "aws cloudtrail get-event-selectors --trail-name TRAIL",
                        "return_field": "DataResources[].Type",
                        "compliant_value": "AWS::S3::Object 또는 AWS::Lambda::Function 포함",
                        "non_compliant_value": "미수집",
                        "console_fix": "Event selectors에 Data events 추가",
                        "cli_fix_cmd": "aws cloudtrail put-event-selectors --trail-name TRAIL --event-selectors file://selectors.json"
                    }
                )

            has_any = False
            for t in trails:
                name = t.get("Name") or t.get("TrailARN") or "trail"
                evidence["trailsChecked"] += 1
                try:
                    sel = ct.get_event_selectors(TrailName=name)
                    ok = False
                    for es in (sel.get("EventSelectors") or []):
                        for dr in (es.get("DataResources") or []):
                            if dr.get("Type") in ("AWS::S3::Object", "AWS::Lambda::Function"):
                                ok = True
                                break
                        if ok: break

                    if ok:
                        evidence["withDataEvents"].append(name)
                    else:
                        evidence["withoutDataEvents"].append(name)

                    evals.append(ServiceEvaluation(
                        service="CloudTrail",
                        resource_id=name,
                        evidence_path="EventSelectors[].DataResources[].Type",
                        checked_field="data_events_present",
                        comparator="exists",
                        expected_value=True,
                        observed_value=ok,
                        passed=ok,
                        decision=("Data events (S3/Lambda) present → passed"
                                  if ok else "No data events for S3/Lambda → failed"),
                        status="COMPLIANT" if ok else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                    has_any = has_any or ok
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="CloudTrail",
                        resource_id=name,
                        evidence_path="get-event-selectors",
                        checked_field="data_events_present",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            status = "COMPLIANT" if has_any else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if status == "COMPLIANT" else "No trails with S3/Lambda data events",
                extract={
                    "code": self.code, "category": "3 (로그/감사/기록 무결성)", "service": "CloudTrail",
                    "console_path": "CloudTrail → Trails → Event selectors",
                    "check_how": "Data events for S3/Lambda 존재 여부",
                    "cli_cmd": "aws cloudtrail get-event-selectors --trail-name TRAIL",
                    "return_field": "DataResources[].Type",
                    "compliant_value": "AWS::S3::Object 또는 AWS::Lambda::Function 포함",
                    "non_compliant_value": "미수집",
                    "console_fix": "Event selectors에 Data events 추가",
                    "cli_fix_cmd": "aws cloudtrail put-event-selectors --trail-name TRAIL --event-selectors file://selectors.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudTrail", resource_id=None,
                    evidence_path="describe_trails",
                    checked_field="trails",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions", extract=None
            )
