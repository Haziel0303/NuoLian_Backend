from fastapi import APIRouter

router = APIRouter(prefix="/tally", tags=["Tally"])

@router.get("/health")
async def tally_health():
    return {
        "service": "Tally API",
        "status": "ok"
    }
