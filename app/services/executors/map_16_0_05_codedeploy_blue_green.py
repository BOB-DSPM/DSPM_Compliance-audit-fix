from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_16_0_05:
    """
    16.0-05 — CodeDeploy: Blue/Green + WITH_TRAFFIC_CONTROL 확인
    - console: CodeDeploy → Applications → Deployment groups
    - check: deploymentStyle.deploymentType == BLUE_GREEN
             AND deploymentStyle.deploymentOption == WITH_TRAFFIC_CONTROL
    - fix: 배포 그룹을 Blue/Green + Traffic control로 구성
    """
    code = "16.0-05"
    title = "CodeDeploy Blue/Green + traffic control"

    def audit(self) -> AuditResult:
        cd = boto3.client("codedeploy")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "applicationsChecked": 0,
            "groupsChecked": 0,
            "compliantGroups": [],
            "nonCompliantGroups": [],
        }

        try:
            # 1) 모든 애플리케이션 나열
            apps: List[str] = []
            paginator = cd.get_paginator("list_applications")
            for page in paginator.paginate():
                apps.extend(page.get("applications", []))

            for app in apps:
                evidence["applicationsChecked"] += 1

                # 2) 애플리케이션의 모든 배포 그룹 나열
                group_names: List[str] = []
                # list_deployment_groups는 paginator가 있음
                dg_paginator = cd.get_paginator("list_deployment_groups")
                for gpage in dg_paginator.paginate(applicationName=app):
                    group_names.extend(gpage.get("deploymentGroups", []) or [])

                for g in group_names:
                    evidence["groupsChecked"] += 1
                    rid = f"{app}/{g}"
                    try:
                        detail = cd.get_deployment_group(
                            applicationName=app,
                            deploymentGroupName=g,
                        ).get("deploymentGroupInfo", {})

                        style = detail.get("deploymentStyle", {}) or {}
                        dtype = style.get("deploymentType")          # 기대: BLUE_GREEN
                        dopt  = style.get("deploymentOption")        # 기대: WITH_TRAFFIC_CONTROL

                        type_ok = (dtype == "BLUE_GREEN")
                        opt_ok  = (dopt == "WITH_TRAFFIC_CONTROL")
                        passed  = bool(type_ok and opt_ok)

                        if passed:
                            evidence["compliantGroups"].append(rid)
                        else:
                            evidence["nonCompliantGroups"].append(
                                {"group": rid, "deploymentType": dtype, "deploymentOption": dopt}
                            )

                        # 배포 타입 판정
                        evals.append(ServiceEvaluation(
                            service="CodeDeploy",
                            resource_id=rid,
                            evidence_path="deploymentGroupInfo.deploymentStyle.deploymentType",
                            checked_field="deploymentStyle.deploymentType",
                            comparator="eq",
                            expected_value="BLUE_GREEN",
                            observed_value=dtype,
                            passed=type_ok,
                            decision=f"observed {dtype} == BLUE_GREEN → {'passed' if type_ok else 'failed'}",
                            status="COMPLIANT" if type_ok else "NON_COMPLIANT",
                            source="aws-sdk",
                            extra={}
                        ))
                        # 트래픽 컨트롤 판정
                        evals.append(ServiceEvaluation(
                            service="CodeDeploy",
                            resource_id=rid,
                            evidence_path="deploymentGroupInfo.deploymentStyle.deploymentOption",
                            checked_field="deploymentStyle.deploymentOption",
                            comparator="eq",
                            expected_value="WITH_TRAFFIC_CONTROL",
                            observed_value=dopt,
                            passed=opt_ok,
                            decision=f"observed {dopt} == WITH_TRAFFIC_CONTROL → {'passed' if opt_ok else 'failed'}",
                            status="COMPLIANT" if opt_ok else "NON_COMPLIANT",
                            source="aws-sdk",
                            extra={}
                        ))

                    except botocore.exceptions.ClientError as ie:
                        evals.append(ServiceEvaluation(
                            service="CodeDeploy",
                            resource_id=rid,
                            evidence_path="deploymentGroupInfo",
                            checked_field="deploymentStyle",
                            comparator=None,
                            expected_value=None,
                            observed_value=None,
                            passed=None,
                            decision="cannot evaluate: missing permissions or not found",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"error": str(ie)}
                        ))

            # 3) 종합 상태 결정
            if evidence["groupsChecked"] == 0:
                status = "SKIPPED"
                reason = "No applications or deployment groups found"
            else:
                # 한 개라도 불일치면 NON_COMPLIANT (ALL 기준)
                status = "NON_COMPLIANT" if evidence["nonCompliantGroups"] else "COMPLIANT"
                reason = None if status == "COMPLIANT" else "Some groups are not Blue/Green with traffic control"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=reason,
                extract={
                    "code": self.code,
                    "category": "16 (변경관리/형상관리/CI·CD)",
                    "service": "CodeDeploy",
                    "console_path": "CodeDeploy → Applications → Deployment groups",
                    "check_how": "deploymentStyle: BLUE_GREEN + WITH_TRAFFIC_CONTROL",
                    "cli_cmd": "aws deploy get-deployment-group --application-name APP --deployment-group-name GRP",
                    "return_field": "deploymentStyle.deploymentOption",
                    "compliant_value": "WITH_TRAFFIC_CONTROL",
                    "non_compliant_value": "IN_PLACE 등",
                    "console_fix": "배포 그룹을 Blue/Green + Traffic control로 구성",
                    "cli_fix_cmd": (
                        "aws deploy update-deployment-group "
                        "--application-name APP --current-deployment-group-name GRP "
                        "--deployment-style deploymentType=BLUE_GREEN,deploymentOption=WITH_TRAFFIC_CONTROL"
                    )
                }
            )

        except botocore.exceptions.ClientError as e:
            # 루트 레벨 권한 부족 등
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CodeDeploy",
                    resource_id=None,
                    evidence_path="applications/deploymentGroups",
                    checked_field="deploymentStyle",
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
