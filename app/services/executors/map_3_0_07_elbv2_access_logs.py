from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_3_0_07:
    code = "3.0-07"
    title = "ELB/NLB Access Logs enabled"

    def audit(self) -> AuditResult:
        elb = boto3.client("elbv2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"totalLBs": 0, "nonCompliant": []}

        try:
            paginator = elb.get_paginator("describe_load_balancers")
            lbs = []
            for page in paginator.paginate():
                lbs.extend(page.get("LoadBalancers", []))

            evidence["totalLBs"] = len(lbs)

            for lb in lbs:
                arn = lb["LoadBalancerArn"]
                name = lb.get("LoadBalancerName", arn)
                try:
                    attrs = elb.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
                    # access_logs.s3.enabled == "true" 여야 함
                    enabled = False
                    for a in attrs:
                        if a["Key"] == "access_logs.s3.enabled":
                            enabled = (a["Value"].lower() == "true")
                            break

                    passed = enabled
                    if not passed:
                        evidence["nonCompliant"].append(name)

                    evals.append(ServiceEvaluation(
                        service="ELBv2",
                        resource_id=name,
                        evidence_path="Attributes[?Key=='access_logs.s3.enabled'].Value",
                        checked_field="access_logs.s3.enabled",
                        comparator="eq",
                        expected_value=True,
                        observed_value=enabled,
                        passed=passed,
                        decision=f"observed {enabled} == True → {'passed' if passed else 'failed'}",
                        status="COMPLIANT" if passed else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))
                except botocore.exceptions.ClientError as ie:
                    evals.append(ServiceEvaluation(
                        service="ELBv2",
                        resource_id=name,
                        evidence_path="DescribeLoadBalancerAttributes",
                        checked_field="access_logs.s3.enabled",
                        comparator=None, expected_value=None, observed_value=None, passed=None,
                        decision="cannot evaluate: missing permissions",
                        status="SKIPPED", source="aws-sdk", extra={"error": str(ie)}
                    ))

            if evidence["totalLBs"] == 0:
                status, reason = "SKIPPED", "No load balancers"
            else:
                status, reason = ("COMPLIANT", None) if not evidence["nonCompliant"] else ("NON_COMPLIANT", None)

            return AuditResult(
                mapping_code=self.code, title=self.title, status=status,
                evaluations=evals, evidence=evidence, reason=reason,
                extract={
                    "code": self.code,
                    "category": "3 (로그/감사/기록 무결성)",
                    "service": "ELB/NLB",
                    "console_path": "EC2 → Load Balancers → 속성",
                    "check_how": "Access logs → S3 전송 활성",
                    "cli_cmd": "aws elbv2 describe-load-balancer-attributes --load-balancer-arn ARN",
                    "return_field": "access_logs.s3.enabled",
                    "compliant_value": "TRUE",
                    "non_compliant_value": "FALSE",
                    "console_fix": "Load balancer → Edit attributes → Enable access logs",
                    "cli_fix_cmd": "aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN --attributes Key=access_logs.s3.enabled,Value=true"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="ELBv2", resource_id=None,
                    evidence_path="LoadBalancers", checked_field="access_logs.s3.enabled",
                    comparator=None, expected_value=None, observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )], evidence={}, reason="Missing permissions", extract=None
            )
