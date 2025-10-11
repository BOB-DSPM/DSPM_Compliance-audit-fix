# app/services/executors/map_2_0_09_alb_tls.py

from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_2_0_09:
    code = "2.0-09"
    title = "ALB/ACM"

    def audit(self) -> AuditResult:
        elbv2 = boto3.client("elbv2")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "listenersChecked": 0,
            "nonHttps": [],
            "badPolicy": [],
        }

        try:
            # 모든 ALB 가져오기
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
            for lb in lbs:
                lb_arn = lb["LoadBalancerArn"]
                # 리스너 나열
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                for lst in listeners:
                    evidence["listenersChecked"] += 1
                    rid = f"{lb_arn}:{lst['ListenerArn']}"
                    proto = lst.get("Protocol")
                    policy = None
                    if proto == "HTTPS":
                        # HTTPS일 때만 SslPolicy가 있음
                        policy = lst.get("SslPolicy")

                    # 1) 프로토콜이 HTTPS 인가?
                    p_pass = (proto == "HTTPS")
                    if not p_pass:
                        evidence["nonHttps"].append(rid)

                    evals.append(ServiceEvaluation(
                        service="ALB",
                        resource_id=rid,
                        evidence_path="Listeners[].Protocol",
                        checked_field="Protocol",
                        comparator="eq",
                        expected_value="HTTPS",
                        observed_value=proto,
                        passed=p_pass,
                        decision=f'observed "{proto}" == "HTTPS" → {"passed" if p_pass else "failed"}',
                        status="COMPLIANT" if p_pass else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={}
                    ))

                    # 2) TLS 정책이 최신 계열인가? (간단판: 이름에 'TLS' 포함으로 판단)
                    #    원하면 정규식으로 더 엄격히: r"^ELBSecurityPolicy-TLS.*"
                    if p_pass:  # HTTPS일 때만 검사
                        pol_pass = bool(policy and ("TLS" in policy))
                        if not pol_pass:
                            evidence["badPolicy"].append({"listener": rid, "policy": policy})

                        evals.append(ServiceEvaluation(
                            service="ALB",
                            resource_id=rid,
                            evidence_path="Listeners[].SslPolicy",
                            checked_field="SslPolicy",
                            comparator="regex",  # 혹은 "contains" 로 완화 가능
                            expected_value=r"^ELBSecurityPolicy-TLS.*",
                            observed_value=policy,
                            passed=pol_pass,
                            decision=("policy matches ^ELBSecurityPolicy-TLS.* → "
                                      f'{"passed" if pol_pass else "failed"} (observed: {policy})'),
                            status="COMPLIANT" if pol_pass else "NON_COMPLIANT",
                            source="aws-sdk",
                            extra={}
                        ))

            status = "COMPLIANT"
            if evidence["nonHttps"] or evidence["badPolicy"]:
                status = "NON_COMPLIANT"

            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason=None,
                extract={
                    "code": self.code,
                    "category": "2 (암호화/KMS/TLS/At-rest)",
                    "service": "ALB/ACM",
                    "console_path": "EC2 → Load Balancers",
                    "check_how": "HTTPS 리스너/최신 TLS",
                    "cli_cmd": "aws elbv2 describe-listeners --load-balancer-arn ARN",
                    "return_field": "Protocol, SslPolicy",
                    "compliant_value": "HTTPS, 최신",
                    "non_compliant_value": "HTTP/미설정",
                    "console_fix": "ALB → Listeners → Add HTTPS → 인증서 연결",
                    "cli_fix_cmd": ("aws elbv2 create-listener --load-balancer-arn ARN --protocol HTTPS "
                                    "--port 443 --certificates CertificateArn=ARN "
                                    "--default-actions Type=forward,TargetGroupArn=TGA")
                }
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="ALB",
                    resource_id=None,
                    evidence_path="Listeners[].(Protocol,SslPolicy)",
                    checked_field="Protocol/SslPolicy",
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
