from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_16_0_02:
    code = "16.0-02"
    title = "CodePipeline manual approval stage"

    def audit(self) -> AuditResult:
        cp = boto3.client("codepipeline")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"pipelinesChecked": 0, "withApproval": [], "withoutApproval": []}

        try:
            # 파이프라인 목록
            pipelines: List[Dict[str, Any]] = []
            paginator = cp.get_paginator("list_pipelines")
            for page in paginator.paginate():
                pipelines.extend(page.get("pipelines", []))

            for p in pipelines:
                name = p.get("name")
                evidence["pipelinesChecked"] += 1
                try:
                    # 정의를 불러와 Category가 Approval인 액션이 있는지 확인
                    pipe_def = cp.get_pipeline(name=name).get("pipeline", {})
                    stages = pipe_def.get("stages", []) or []
                    has_manual = False
                    where = None

                    for st in stages:
                        st_name = st.get("name")
                        actions = st.get("actions", []) or []
                        for a in actions:
                            at = a.get("actionTypeId", {})
                            if at.get("category") == "Approval":
                                has_manual = True
                                where = {"stage": st_name, "action": a.get("name")}
                                break
                        if has_manual:
                            break

                    if has_manual:
                        evidence["withApproval"].append({"pipeline": name, **(where or {})})
                    else:
                        evidence["withoutApproval"].append(name)

                    evals.append(ServiceEvaluation(
                        service="CodePipeline",
                        resource_id=name,
                        evidence_path="pipeline.stages.actions.actionTypeId.category",
                        checked_field="actionTypeId.category",
                        comparator="contains",
                        expected_value="Approval",
                        observed_value="Approval" if has_manual else "None",
                        passed=has_manual,
                        decision=f"Manual approval {'found' if has_manual else 'not found'} → "
                                 f"{'passed' if has_manual else 'failed'}",
                        status="COMPLIANT" if has_manual else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"foundAt": where} if where else {}
                    ))

                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="CodePipeline",
                        resource_id=name,
                        evidence_path="pipeline",
                        checked_field="actionTypeId.category",
                        comparator=None,
                        expected_value=None,
                        observed_value=None,
                        passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED",
                        source="aws-sdk",
                        extra={"error": str(ie)}
                    ))

            total = evidence["pipelinesChecked"]
            status = "SKIPPED" if total == 0 else ("COMPLIANT" if evidence["withApproval"] else "NON_COMPLIANT")
            reason = None if status != "SKIPPED" else "No pipelines found"

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
                    "service": "CodePipeline",
                    "console_path": "CodePipeline → Stages",
                    "check_how": "Manual approval(Approval 카테고리) 액션 포함 여부",
                    "cli_cmd": "aws codepipeline get-pipeline --name PIPELINE",
                    "return_field": "stages[].actions[].actionTypeId.category == 'Approval'",
                    "compliant_value": "ManualApproval 포함",
                    "non_compliant_value": "ManualApproval 없음",
                    "console_fix": "스테이지에 Manual approval 액션 추가",
                    "cli_fix_cmd": "aws codepipeline update-pipeline --cli-input-json file://pipeline.json"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CodePipeline",
                    resource_id=None,
                    evidence_path="pipelines",
                    checked_field="actionTypeId.category",
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
