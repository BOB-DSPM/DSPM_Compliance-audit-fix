from fastapi import APIRouter
router = APIRouter()

@router.get("", summary="Health")
def health():
    return {"status": "ok"}
