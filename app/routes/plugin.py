import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter(prefix="/api/plugin", tags=["Plugin"])
logger = logging.getLogger("plugin")

PLUGIN_SERVICE_TOKEN = os.getenv("PLUGIN_SERVICE_TOKEN", "")
AUTO_REPLIES = {
    "注册公司时效多久？": "通常情况下，注册公司大约需要 2 到 4 周，具体会根据资料准备、签字进度和当地审批情况有所不同。",
    "你好": "你好，欢迎联系诺联客服，请问想了解公司注册、银行开户，还是签证支持？",
}


def _require_service_token(x_service_token: str | None) -> None:
    if not PLUGIN_SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Plugin token is not configured")
    if x_service_token != PLUGIN_SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid service token")


def _extract_message_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.strip()
    if not isinstance(payload, dict):
        return ""
    for key in ("message", "content", "text", "payload"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


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
    message_text = _extract_message_text(payload)
    reply_text = AUTO_REPLIES.get(message_text)

    return {
        "status": "ok",
        "message": "Plugin endpoint received the request",
        "matched_text": message_text or None,
        "reply": reply_text,
        "received_userid": request.headers.get("userid"),
        "payload": payload,
    }
