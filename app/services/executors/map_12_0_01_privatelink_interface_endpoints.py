from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_12_0_01:
    code = "12.0-01"
    title = "PrivateLink(Interface VPC Endpoints) 존재/Private DNS"

    def audit(self) -> AuditResult:
        ec2 = boto3.client("ec2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {"endpoints": 0, "interface_eps": 0, "private_dns_enabled": 0, "sample": []}

        try:
            paginator = ec2.get_paginator("describe_vpc_endpoints")
            eps = []
            for page in paginator.paginate():
                eps.extend(page.get("VpcEndpoints", []) or [])
            evidence["endpoints"] = len(eps)

            for ep in eps:
                if ep.get("VpcEndpointType") == "Interface":
                    evidence["interface_eps"] += 1
                    pdns = bool(ep.get("PrivateDnsEnabled"))
                    if pdns:
                        evidence["private_dns_enabled"] += 1

                    rid = ep.get("VpcEndpointId")
                    svc = ep.get("ServiceName")
                    evidence["sample"].append({"id": rid, "service": svc, "privateDns": pdns})
                    evals.append(ServiceEvaluation(
                        service="EC2",
                        resource_id=rid,
                        evidence_path="VpcEndpoints[*].{VpcEndpointType,PrivateDnsEnabled}",
                        checked_field="PrivateDnsEnabled",
                        comparator="eq",
                        expected_value=True,
                        observed_value=pdns,
                        passed=pdns,
                        decision=f"Interface endpoint PrivateDnsEnabled == True → {'passed' if pdns else 'failed'}",
                        status="COMPLIANT" if pdns else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"service": svc}
                    ))

            # 매핑 정의상 "존재"가 핵심 → Interface EP가 1개 이상이어야 함.
            # Private DNS까지 켜진 개수를 보조 지표로 제공.
            has_interface = evidence["interface_eps"] >= 1
            overall = "COMPLIANT" if has_interface else "NON_COMPLIANT"

            # Interface EP가 1개도 없을 경우, 최소 한 건 FAIL 기록 추가
            if not has_interface:
                evals.append(ServiceEvaluation(
                    service="EC2",
                    resource_id=None,
                    evidence_path="VpcEndpoints[*].VpcEndpointType",
                    checked_field="Interface endpoints count",
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
                mapping_code=self.code, title=self.title, status=overall,
                evaluations=evals, evidence=evidence, reason=None,
                extract={
                    "code": self.code, "category": "12 (데이터 전송/제3자 제공)", "service": "VPC",
                    "console_path": "VPC → Endpoints",
                    "check_how": "Interface 타입 VPC Endpoint 존재/Private DNS 여부",
                    "cli_cmd": "aws ec2 describe-vpc-endpoints",
                    "return_field": "VpcEndpoints[].{VpcEndpointType,PrivateDnsEnabled}",
                    "compliant_value": "Interface EP 존재(>=1), Private DNS 권장",
                    "non_compliant_value": "없음(0)",
                    "console_fix": "Interface 타입 Endpoint 생성 및 Private DNS 활성화",
                    "cli_fix_cmd": "aws ec2 create-vpc-endpoint --vpc-id vpc-XXX --service-name com.amazonaws.REGION.execute-api --vpc-endpoint-type Interface --subnet-ids subnet-... --private-dns-enabled"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code, title=self.title, status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="EC2", resource_id=None,
                    evidence_path="VpcEndpoints", checked_field="VpcEndpointType",
                    comparator="exists", expected_value=True,
                    observed_value=None, passed=None,
                    decision="cannot evaluate: missing permissions or API error",
                    status="SKIPPED", source="aws-sdk", extra={"error": str(e)}
                )],
                evidence={}, reason="Missing permissions or API error", extract=None
            )
