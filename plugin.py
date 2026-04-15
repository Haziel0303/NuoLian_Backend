import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter(prefix="/api/plugin", tags=["Plugin"])
logger = logging.getLogger("plugin")

PLUGIN_SERVICE_TOKEN = os.getenv("PLUGIN_SERVICE_TOKEN", "")


def _require_service_token(x_service_token: str | None) -> None:
    if not PLUGIN_SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Plugin token is not configured")
    if x_service_token != PLUGIN_SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid service token")


@router.get("/health")
async def plugin_health(x_service_token: str | None = Header(default=None)) -> dict[str, str]:
    _require_service_token(x_service_token)
    return {"service": "plugin", "status": "ok"}


@router.post("/hook")
async def plugin_hook(
    request: Request,
    x_service_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_service_token(x_service_token)

    try:
        payload = await request.json()
    except Exception:
        payload = {"raw_body": (await request.body()).decode("utf-8", "replace")}

    logger.warning(
        "plugin hook request path=%s content_type=%s user_id=%s payload=%s",
        request.url.path,
        request.headers.get("content-type", ""),
        request.headers.get("userid", ""),
        payload,
    )

    return {
        "status": "ok",
        "message": "Plugin endpoint received the request",
        "received_userid": request.headers.get("userid"),
        "payload": payload,
    }
