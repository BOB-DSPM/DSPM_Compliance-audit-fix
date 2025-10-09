# app/routers/audit.py
from fastapi import APIRouter, Path
from app.services.audit_service import AuditService

router = APIRouter()

@router.post("/{framework}/_all", summary="(프레임워크) 전체 감사 수행")
def audit_framework(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
):
    # 경로 파라미터에 공백(%20 등) 들어온 경우 대비
    framework = framework.strip()
    svc = AuditService()
    return svc.audit_compliance(framework)

@router.post("/{framework}/{req_id:int}", summary="(항목) 감사 수행")
def audit_requirement(
    framework: str = Path(..., description="예: ISMS-P / GDPR / iso-27001"),
    req_id: int = Path(..., description="매핑 백엔드의 requirement.id"),
):
    # 경로 파라미터에 공백(%20 등) 들어온 경우 대비
    framework = framework.strip()
    svc = AuditService()
    return svc.audit_requirement(framework, req_id)
