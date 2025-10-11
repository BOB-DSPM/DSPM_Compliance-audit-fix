from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_7_0_02:
    code = "7.0-02"
    title = "GuardDuty detector enabled"

    def audit(self) -> AuditResult:
        gd = boto3.client("guardduty")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"detectorIds": [], "disabledDetectors": []}

        try:
            # 1) Detector 존재 여부
            det_ids = gd.list_detectors().get("DetectorIds", [])
            evidence["detectorIds"] = det_ids

            if not det_ids:
                # Detector 자체가 없으면 비준수
                evals.append(ServiceEvaluation(
                    service="GuardDuty",
                    resource_id=None,
                    evidence_path="DetectorIds",
                    checked_field="detector_exists",
                    comparator="exists",
                    expected_value=True,
                    observed_value=False,
                    passed=False,
                    decision="observed no detector → failed",
                    status="NON_COMPLIANT",
                    source="aws-sdk",
                    extra={}
                ))
                return AuditResult(
                    mapping_code=self.code,
                    title=self.title,
                    status="NON_COMPLIANT",
                    evaluations=evals,
                    evidence=evidence,
                    reason=None,
                    extract={
                        "code": self.code,
                        "category": "7 (모니터링/임계치/시간동기화)",
                        "service": "GuardDuty",
                        "console_path": "GuardDuty → Detectors",
                        "check_how": "탐지기(Detector) 활성 여부",
                        "cli_cmd": "aws guardduty list-detectors",
                        "return_field": "DetectorIds",
                        "compliant_value": "존재",
                        "non_compliant_value": "없음",
                        "console_fix": "GuardDuty 활성화 후 탐지기 생성",
                        "cli_fix_cmd": "aws guardduty create-detector --enable"
                    }
                )

            # 2) 각 Detector 상태 확인 (ENABLED 여야 함)
            all_enabled = True
            for did in det_ids:
                try:
                    st = gd.get_detector(DetectorId=did).get("Status", "DISABLED")
                    enabled = (st.upper() == "ENABLED")
                    if not enabled:
                        all_enabled = False
                        evidence["disabledDetectors"].append(did)

                    evals.append(ServiceEvaluation(
                        service="GuardDuty",
                        resource_id=did,
                        evidence_path="GetDetector.Status",
                        checked_field="Status",
                        comparator="eq",
                        expected_value="ENABLED",
                        observed_value=st,
                        passed=enabled,
                        decision=f"observed {st} == ENABLED → {'passed' if enabled else 'failed'}",
                        status="COMPLIANT" if enabled else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="GuardDuty",
                        resource_id=did,
                        evidence_path="GetDetector",
                        checked_field="Status",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            overall = "COMPLIANT" if all_enabled else "NON_COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=overall,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "7 (모니터링/임계치/시간동기화)",
                    "service": "GuardDuty",
                    "console_path": "GuardDuty → Detectors",
                    "check_how": "탐지기(Detector) 존재 및 ENABLED",
                    "cli_cmd": "aws guardduty get-detector --detector-id DETECTOR_ID",
                    "return_field": "Status",
                    "compliant_value": "ENABLED",
                    "non_compliant_value": "DISABLED",
                    "console_fix": "GuardDuty 탐지기 ENABLED로 전환",
                    "cli_fix_cmd": "aws guardduty update-detector --detector-id DETECTOR_ID --enable"
                }
            )

        except botocore.exceptions.ClientError as e:
            # 권한 부족/액세스 에러 등
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="GuardDuty",
                    resource_id=None,
                    evidence_path="ListDetectors",
                    checked_field="DetectorIds",
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
