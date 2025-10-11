from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_8_0_07:
    """
    8.0-07 — AWS Network Firewall
    기준: 방화벽이 1개 이상 존재하면 COMPLIANT, 없으면 NON_COMPLIANT
    """
    code = "8.0-07"
    title = "AWS Network Firewall deployed"

    def audit(self) -> AuditResult:
        nfw = boto3.client("network-firewall")  # 서비스 이름에 하이픈 포함
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "firewallCount": 0,
            "sampleFirewalls": [],  # 최대 5개 샘플
        }

        try:
            # paginator가 없는 환경도 있어 NextToken 루프 수동 처리
            next_token = None
            names: List[str] = []
            while True:
                params = {"MaxResults": 100}
                if next_token:
                    params["NextToken"] = next_token
                resp = nfw.list_firewalls(**params)
                summaries = resp.get("Firewalls", []) or []
                for s in summaries:
                    if "FirewallName" in s:
                        names.append(s["FirewallName"])
                    elif "FirewallArn" in s:
                        names.append(s["FirewallArn"])
                next_token = resp.get("NextToken")
                if not next_token:
                    break

            evidence["firewallCount"] = len(names)
            evidence["sampleFirewalls"] = names[:5]

            passed = evidence["firewallCount"] >= 1
            evals.append(ServiceEvaluation(
                service="Network Firewall",
                resource_id="account/region",
                evidence_path="Firewalls (count)",
                checked_field="firewallCount",
                comparator="ge",
                expected_value=1,
                observed_value=evidence["firewallCount"],
                passed=passed,
                decision=f"observed {evidence['firewallCount']} >= 1 → {'passed' if passed else 'failed'}",
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                source="aws-sdk",
                extra={"sample": evidence["sampleFirewalls"]}
            ))

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="COMPLIANT" if passed else "NON_COMPLIANT",
                evaluations=evals,
                evidence=evidence,
                reason=None if passed else "No Network Firewall present in this account/region",
                extract={
                    "code": self.code,
                    "category": "8 (네트워크/VPC/Public 노출)",
                    "service": "AWS Network Firewall",
                    "console_path": "VPC → Network Firewall",
                    "check_how": "list-firewalls 로 방화벽 개수 확인",
                    "cli_cmd": "aws network-firewall list-firewalls",
                    "return_field": "Firewalls",
                    "compliant_value": "존재(>=1)",
                    "non_compliant_value": "없음",
                    "console_fix": "방화벽/정책 생성 후 서브넷에 연결",
                    "cli_fix_cmd": "aws network-firewall create-firewall --firewall-name fw "
                                   "--vpc-id vpc-XXX --subnet-mappings SubnetId=subnet-XXX "
                                   "--firewall-policy-arn POLICY_ARN"
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="Network Firewall",
                    resource_id=None,
                    evidence_path="list-firewalls",
                    checked_field="firewallCount",
                    comparator=None,
                    expected_value=None,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions or API disabled",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)}
                )],
                evidence={},
                reason="Missing permissions or service not available",
                extract=None
            )
