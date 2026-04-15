from fastapi import APIRouter, HTTPException

from app.db import check_database_connection

router = APIRouter(prefix="/database", tags=["Database"])


@router.get("/health")
async def database_health():
    try:
        connection_info = check_database_connection()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "service": "PostgreSQL",
                "status": "error",
                "message": str(exc),
            },
        ) from exc

    return {
        "service": "PostgreSQL",
        "status": "ok",
        **connection_info,
    }
