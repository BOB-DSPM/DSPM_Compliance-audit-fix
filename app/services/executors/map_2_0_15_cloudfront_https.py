import math
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from app.models.schemas import AuditResult, ServiceEvaluation
from app.core.config import settings

# cloudfront 클라이언트 팩토리 (app.core.aws.cloudfront 가 있으면 그걸 쓰고, 없으면 boto3 사용)
try:
    from app.core.aws import cloudfront as _cf_factory
    def _cloudfront():
        return _cf_factory()
except Exception:
    import boto3
    def _cloudfront():
        # CloudFront는 글로벌 서비스(리전 불필요)지만 boto3가 리전을 요구할 경우를 대비
        region = getattr(settings, "AWS_REGION", None)
        return boto3.client("cloudfront", region_name=region)

ALLOWED = {"redirect-to-https", "https-only"}

def _final_status(evals: List[ServiceEvaluation]) -> str:
    if any(e.status == "ERROR" for e in evals):
        return "ERROR"
    if any(e.status == "NON_COMPLIANT" for e in evals):
        return "NON_COMPLIANT"
    if evals and all(e.status == "SKIPPED" for e in evals):
        return "SKIPPED"
    return "COMPLIANT" if evals else "SKIPPED"


class Exec_2_0_15:
    """
    매핑코드: 2.0-15
    점검내용: CloudFront 배포의 모든 Behavior가 HTTPS 강제(redirect-to-https 또는 https-only)인지
    기준: 모든 Behavior.ViewerProtocolPolicy ∈ {"redirect-to-https", "https-only"}
    """
    code = "2.0-15"

    def _list_all_distributions(self) -> List[Dict[str, Any]]:
        """
        CloudFront ListDistributions는 페이지네이션(NextMarker) 사용.
        전 배포를 수집해 Items 리스트로 반환.
        """
        client = _cloudfront()
        items: List[Dict[str, Any]] = []

        marker = None
        while True:
            if marker:
                resp = client.list_distributions(Marker=marker)
            else:
                resp = client.list_distributions()
            dl = resp.get("DistributionList", {})
            page_items = dl.get("Items", []) or []
            items.extend(page_items)
            if dl.get("IsTruncated"):
                marker = dl.get("NextMarker")
            else:
                break
        return items

    @staticmethod
    def _collect_vpp(distribution: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        배포의 Default + CacheBehaviors에서 ViewerProtocolPolicy 추출
        반환 예: [{"path":"default","policy":"redirect-to-https"}, {"path":"/api/*","policy":"allow-all"}]
        """
        out: List[Dict[str, str]] = []
        dcb = distribution.get("DefaultCacheBehavior") or {}
        if dcb:
            out.append({"path": "default", "policy": dcb.get("ViewerProtocolPolicy", "")})

        cb = distribution.get("CacheBehaviors", {})
        for b in (cb.get("Items") or []):
            path = b.get("PathPattern", "")
            policy = b.get("ViewerProtocolPolicy", "")
            out.append({"path": path or "(unknown)", "policy": policy})
        return out

    def audit(self) -> AuditResult:
        evaluations: List[ServiceEvaluation] = []
        evidence_summary: Dict[str, Any] = {}

        # 1) 전체 배포 나열
        try:
            dists = self._list_all_distributions()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("AccessDenied", "AccessDeniedException"):
                evaluations.append(ServiceEvaluation(
                    service="CloudFront",
                    resource_id=None,
                    evidence_path="DistributionList.Items",
                    checked_field="ViewerProtocolPolicy for all behaviors",
                    comparator="exists",
                    expected_value="policies in {'redirect-to-https','https-only'}",
                    observed_value=None,
                    passed=None,
                    decision="cannot evaluate: missing permissions",
                    status="SKIPPED",
                    source="aws-sdk",
                    extra={"missingPermissions": ["cloudfront:ListDistributions"], "error": str(e)}
                ))
                return AuditResult(mapping_code=self.code,
                                   status=_final_status(evaluations),
                                   evaluations=evaluations,
                                   evidence={},
                                   reason="Missing permissions for CloudFront read")
            evaluations.append(ServiceEvaluation(
                service="CloudFront",
                resource_id=None,
                evidence_path="DistributionList.Items",
                checked_field="ViewerProtocolPolicy for all behaviors",
                comparator="exists",
                expected_value="policies in {'redirect-to-https','https-only'}",
                observed_value=None,
                passed=None,
                decision="check failed due to exception",
                status="ERROR",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, status="ERROR", evaluations=evaluations, reason=str(e))
        except Exception as e:
            evaluations.append(ServiceEvaluation(
                service="CloudFront",
                resource_id=None,
                evidence_path="DistributionList.Items",
                checked_field="ViewerProtocolPolicy for all behaviors",
                comparator="exists",
                expected_value="policies in {'redirect-to-https','https-only'}",
                observed_value=None,
                passed=None,
                decision="check failed due to exception",
                status="ERROR",
                source="aws-sdk",
                extra={"error": str(e)}
            ))
            return AuditResult(mapping_code=self.code, status="ERROR", evaluations=evaluations, reason=str(e))

        if not dists:
            # 배포가 없으면 SKIPPED
            evaluations.append(ServiceEvaluation(
                service="CloudFront",
                resource_id=None,
                evidence_path="DistributionList.Items",
                checked_field="Distributions count",
                comparator="ge",
                expected_value=1,
                observed_value=0,
                passed=False,
                decision="no CloudFront distributions",
                status="SKIPPED",
                source="aws-sdk",
                extra={}
            ))
            return AuditResult(mapping_code=self.code,
                               status=_final_status(evaluations),
                               evaluations=evaluations,
                               evidence={"distributionCount": 0},
                               reason="No CloudFront distributions")

        # 2) 각 배포 평가
        compliant_cnt = 0
        non_compliant_cnt = 0
        error_cnt = 0
        skipped_cnt = 0

        for dist in dists:
            dist_id = dist.get("Id")
            arn = dist.get("ARN", dist_id)
            behaviors = self._collect_vpp(dist)
            # 정책이 허용 세트 안에 있는지 전부 검사
            bad = [b for b in behaviors if (b.get("policy") or "").lower() not in ALLOWED]

            observed = [{"path": b["path"], "policy": b.get("policy", "")} for b in behaviors]
            expected = "each policy ∈ {'redirect-to-https','https-only'}"
            all_ok = len(bad) == 0
            decision = (
                f"{'all behaviors allowed' if all_ok else f'{len(bad)} behaviors not allowed'}"
            )

            status = "COMPLIANT" if all_ok else "NON_COMPLIANT"
            if status == "COMPLIANT":
                compliant_cnt += 1
            else:
                non_compliant_cnt += 1

            evaluations.append(ServiceEvaluation(
                service="CloudFront",
                resource_id=arn,
                evidence_path="DefaultCacheBehavior.ViewerProtocolPolicy, CacheBehaviors.Items[].ViewerProtocolPolicy",
                checked_field="ViewerProtocolPolicy",
                comparator="contains",
                expected_value=expected,
                observed_value=observed,
                passed=all_ok,
                decision=decision,
                status=status,
                source="aws-sdk",
                extra={"nonAllowed": bad}
            ))

        evidence_summary = {
            "distributions": len(dists),
            "compliant": compliant_cnt,
            "nonCompliant": non_compliant_cnt,
            "skipped": skipped_cnt,
            "errors": error_cnt
        }

        return AuditResult(
            mapping_code=self.code,
            status=_final_status(evaluations),
            evaluations=evaluations,
            evidence=evidence_summary
        )
