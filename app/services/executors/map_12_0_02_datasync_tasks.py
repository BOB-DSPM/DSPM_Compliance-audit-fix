from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation


class Exec_12_0_02:
    code = "12.0-02"
    title = "DataSync Tasks (전송 정책·암호화 기본 점검: Task 존재 여부)"

    def audit(self) -> AuditResult:
        ds = boto3.client("datasync")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"taskCount": 0, "taskArns": []}

        try:
            # list_tasks는 NextToken 페이지네이션(비정형) 형태 → 루프 처리
            task_arns: List[str] = []
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = ds.list_tasks(**kwargs)
                for t in resp.get("Tasks", []):
                    arn = t.get("TaskArn")
                    if arn:
                        task_arns.append(arn)
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            evidence["taskCount"] = len(task_arns)
            evidence["taskArns"] = task_arns[:10]  # 너무 길면 일부만 증거로

            observed = len(task_arns)
            passed = observed >= 1

            evals.append(ServiceEvaluation(
                service="DataSync",
                resource_id="account/region",
                evidence_path="Tasks[].TaskArn",
                checked_field="Tasks count",
                comparator="ge",
                expected_value=1,
                observed_value=observed,
                passed=passed,
                decision=f"observed {observed} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={}
            ))

            status = "COMPLIANT" if passed else "NON_COMPLIANT"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "No DataSync tasks found",
                extract={
                    "code": self.code,
                    "category": "12 (데이터 전송/제3자 제공)",
                    "service": "DataSync",
                    "console_path": "DataSync → Tasks",
                    "check_how": "전송 정책·암호화 구성 전제: Task 존재 여부",
                    "cli_cmd": "aws datasync list-tasks",
                    "return_field": "Tasks",
                    "compliant_value": "존재(≥1)",
                    "non_compliant_value": "없음(0)",
                    "console_fix": "DataSync 콘솔에서 Task 생성(소스/대상 위치 및 암호화 옵션 포함)",
                    "cli_fix_cmd": "aws datasync create-task --source-location-arn SRC --destination-location-arn DST"
                }
            )

        except botocore.exceptions.ClientError as e:
            # 권한/액세스 문제 등 → SKIPPED
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="DataSync",
                    resource_id=None,
                    evidence_path="Tasks",
                    checked_field="list-tasks",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions or API error",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions or API error",
                extract=None
            )
