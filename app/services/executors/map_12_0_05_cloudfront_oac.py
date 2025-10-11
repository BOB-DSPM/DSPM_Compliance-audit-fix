from __future__ import annotations
from typing import List, Dict, Any
import boto3, botocore
from app.models.schemas import AuditResult, ServiceEvaluation

class Exec_12_0_05:
    """
    12.0-05 CloudFront OAC: S3 오리진은 OAC(신규) 또는 OAI(레거시)로 사설화되어야 함.
    판단 기준(오리진 단위):
      - OAC 사용: OriginAccessControlId 존재 → COMPLIANT
      - OAI 사용: S3OriginConfig.OriginAccessIdentity 존재(빈 문자열 아님) → COMPLIANT
      - 그 외(퍼블릭/직접 접근): NON_COMPLIANT
    배포 단위 최종 상태:
      - 하나라도 NON_COMPLIANT 오리진이 있으면 배포는 NON_COMPLIANT
    전체 매핑 최종 상태:
      - 하나라도 NON_COMPLIANT 배포가 있으면 NON_COMPLIANT, 모두 양호면 COMPLIANT
    """
    code = "12.0-05"
    title = "CloudFront OAC/OAI"

    def audit(self) -> AuditResult:
        cf = boto3.client("cloudfront")
        evals: List[ServiceEvaluation] = []
        evidence: Dict[str, Any] = {
            "distributions": 0,
            "checkedOrigins": 0,
            "nonCompliantOrigins": [],  # list of {"distributionId","originId","reason"}
        }

        try:
            paginator = cf.get_paginator("list_distributions")
            dists = []
            for page in paginator.paginate():
                items = page.get("DistributionList", {}).get("Items", []) or []
                dists.extend(items)

            evidence["distributions"] = len(dists)

            for d in dists:
                dist_id = d.get("Id")
                dist_arn = d.get("ARN", dist_id)
                origins = (d.get("Origins", {}) or {}).get("Items", []) or []
                dist_noncompliant = False

                for origin in origins:
                    # S3 오리진만 검사 (Custom 오리진은 스킵)
                    domain = origin.get("DomainName", "") or ""
                    if not domain.endswith(".s3.amazonaws.com") and ".s3-" not in domain and "-s3." not in domain:
                        evals.append(ServiceEvaluation(
                            service="CloudFront",
                            resource_id=f"{dist_id}:{origin.get('Id')}",
                            evidence_path="Origins[].(S3|Custom)",
                            checked_field="S3OriginOnlyCheck",
                            comparator="exists",
                            expected_value=True,
                            observed_value=False,
                            passed=None,
                            decision="custom origin → not in scope",
                            status="SKIPPED",
                            source="aws-sdk",
                            extra={"domain": domain},
                        ))
                        continue

                    evidence["checkedOrigins"] += 1
                    origin_id = origin.get("Id")
                    oac_id = origin.get("OriginAccessControlId")
                    oai_id = None
                    s3cfg = origin.get("S3OriginConfig")
                    if s3cfg:
                        oai_id = (s3cfg.get("OriginAccessIdentity") or "").strip()

                    # OAC 또는 OAI 중 하나라도 있으면 통과
                    has_oac = bool(oac_id)
                    has_oai = bool(oai_id)

                    passed = has_oac or has_oai
                    if not passed:
                        dist_noncompliant = True
                        evidence["nonCompliantOrigins"].append({
                            "distributionId": dist_id,
                            "originId": origin_id,
                            "domain": domain,
                            "reason": "no OAC/OAI",
                        })

                    evals.append(ServiceEvaluation(
                        service="CloudFront",
                        resource_id=f"{dist_id}:{origin_id}",
                        evidence_path="Origins[].(OriginAccessControlId|S3OriginConfig.OriginAccessIdentity)",
                        checked_field="OAC_or_OAI_present",
                        comparator="exists",
                        expected_value=True,
                        observed_value=passed,
                        passed=passed,
                        decision=f"{'OAC/OAI present' if passed else 'no OAC/OAI'} → {'passed' if passed else 'failed'}",
                        status="COMPLIANT" if passed else "NON_COMPLIANT",
                        source="aws-sdk",
                        extra={"OriginAccessControlId": oac_id, "OriginAccessIdentity": oai_id, "domain": domain},
                    ))

                # 배포 단위 결과도 평가 항목으로 남김(요약용)
                evals.append(ServiceEvaluation(
                    service="CloudFront",
                    resource_id=dist_arn,
                    evidence_path="Distribution.Origins",
                    checked_field="AllS3OriginsProtected",
                    comparator="eq",
                    expected_value=True,
                    observed_value=(not dist_noncompliant),
                    passed=(not dist_noncompliant),
                    decision="all S3 origins protected by OAC/OAI"
                             if not dist_noncompliant else "some S3 origins lack OAC/OAI",
                    status="COMPLIANT" if not dist_noncompliant else "NON_COMPLIANT",
                    source="aws-sdk",
                    extra={"distributionId": dist_id},
                ))

            overall_non = len(evidence["nonCompliantOrigins"]) > 0
            status = "NON_COMPLIANT" if overall_non else "COMPLIANT"
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status=status,
                evaluations=evals,
                evidence=evidence,
                reason="Origins without OAC/OAI exist" if overall_non else None,
                extract={
                    "code": self.code,
                    "category": "12 (데이터 전송/제3자 제공)",
                    "service": "CloudFront",
                    "console_path": "CloudFront → Distributions → Origins",
                    "check_how": "OriginAccessControlId or S3OriginConfig.OriginAccessIdentity",
                    "cli_cmd": "aws cloudfront list-distributions",
                    "return_field": "Origins[].OriginAccessControlId",
                    "compliant_value": "존재",
                    "non_compliant_value": "없음",
                    "console_fix": "OAC 생성 후 오리진에 연결(OAI 사용 중이면 유지 가능)",
                    "cli_fix_cmd": "aws cloudfront update-distribution --id DIST_ID --if-match ETag --distribution-config file://cfg.json",
                },
            )

        except botocore.exceptions.ClientError as e:
            return AuditResult(
                mapping_code=self.code,
                title=self.title,
                status="SKIPPED",
                evaluations=[ServiceEvaluation(
                    service="CloudFront",
                    resource_id=None,
                    evidence_path="Distributions",
                    checked_field="Origins",
                    comparator="exists",
                    expected_value=True,
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"error": str(e)},
                )],
                evidence={},
                reason="Missing permissions",
                extract=None,
            )
