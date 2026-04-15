from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from Crypto.Cipher import AES
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from app.faq import match_faq

router = APIRouter()
logger = logging.getLogger("wecom")

WECOM_TOKEN = os.getenv("WECOM_TOKEN", "")
WECOM_ENCODING_AES_KEY = os.getenv("WECOM_ENCODING_AES_KEY", "")
WECOM_CORP_ID = os.getenv("WECOM_CORP_ID", "")
WECOM_APP_SECRET = os.getenv("WECOM_APP_SECRET", "")
SEEN_MSGIDS_PATH = Path("/home/ubuntu/NuoLian_Backend/.wecom_seen_msgids.json")
MAX_SEEN_MSGIDS = 500


class WeComCryptoError(Exception):
    pass


@dataclass(frozen=True)
class KfTextMessage:
    msgid: str
    content: str
    external_userid: str
    open_kfid: str
    origin: dict


def _sha1_signature(token: str, timestamp: str, nonce: str, encrypted: str) -> str:
    items = [token, timestamp, nonce, encrypted]
    items.sort()
    return hashlib.sha1("".join(items).encode("utf-8")).hexdigest()


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise WeComCryptoError("empty decrypted data")
    pad = data[-1]
    if pad < 1 or pad > 32:
        raise WeComCryptoError(f"invalid pkcs7 padding: {pad}")
    if data[-pad:] != bytes([pad]) * pad:
        raise WeComCryptoError("invalid pkcs7 padding bytes")
    return data[:-pad]


def _pkcs7_pad(data: bytes) -> bytes:
    block_size = 32
    pad = block_size - (len(data) % block_size)
    if pad == 0:
        pad = block_size
    return data + bytes([pad]) * pad


def _aes_key_bytes(encoding_aes_key: str) -> bytes:
    try:
        key = base64.b64decode(encoding_aes_key + "=")
    except Exception as e:
        raise WeComCryptoError(f"invalid EncodingAESKey: {e}") from e
    if len(key) != 32:
        raise WeComCryptoError(f"invalid AES key length: {len(key)}")
    return key


def _decrypt_wecom(encrypted_b64: str, encoding_aes_key: str, corp_id: str) -> str:
    key = _aes_key_bytes(encoding_aes_key)
    iv = key[:16]
    try:
        encrypted = base64.b64decode(encrypted_b64)
    except Exception as e:
        raise WeComCryptoError(f"invalid encrypted base64: {e}") from e
    decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
    decrypted = _pkcs7_unpad(decrypted)
    if len(decrypted) < 20:
        raise WeComCryptoError("decrypted payload too short")
    content = decrypted[16:]
    msg_len = struct.unpack(">I", content[:4])[0]
    msg = content[4 : 4 + msg_len]
    receive_id = content[4 + msg_len :].decode("utf-8")
    logger.warning("wecom decrypted receive_id=%s expected_corp_id=%s", receive_id, corp_id)
    if corp_id and receive_id and receive_id != corp_id:
        raise WeComCryptoError(f"CorpID mismatch: expected '{corp_id}', got '{receive_id}'")
    return msg.decode("utf-8")


def _encrypt_wecom(plaintext: str, encoding_aes_key: str, corp_id: str) -> str:
    key = _aes_key_bytes(encoding_aes_key)
    iv = key[:16]
    payload = secrets.token_bytes(16) + struct.pack(">I", len(plaintext.encode("utf-8"))) + plaintext.encode("utf-8") + corp_id.encode("utf-8")
    padded = _pkcs7_pad(payload)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    return base64.b64encode(encrypted).decode("utf-8")


def _extract_encrypt_from_xml(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise WeComCryptoError(f"invalid XML: {e}") from e
    encrypt_node = root.find("Encrypt")
    if encrypt_node is None or not encrypt_node.text:
        raise WeComCryptoError("missing Encrypt field in XML")
    return encrypt_node.text.strip()


def _extract_encrypt(body_text: str) -> str:
    stripped = body_text.strip()
    if not stripped:
        raise WeComCryptoError("empty request body")
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise WeComCryptoError(f"invalid JSON: {e}") from e
        encrypt = data.get("encrypt", "")
        if not isinstance(encrypt, str) or not encrypt.strip():
            raise WeComCryptoError("missing encrypt field in JSON")
        return encrypt.strip()
    return _extract_encrypt_from_xml(stripped)


def _parse_plaintext_xml(xml_text: str) -> dict[str, str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise WeComCryptoError(f"invalid plaintext XML: {e}") from e
    parsed: dict[str, str] = {}
    for child in root:
        parsed[child.tag] = (child.text or "").strip()
    return parsed


def _parse_plaintext_message(plaintext: str) -> dict:
    stripped = plaintext.strip()
    if not stripped:
        raise WeComCryptoError("empty plaintext message")
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise WeComCryptoError(f"invalid plaintext JSON: {e}") from e
        if not isinstance(data, dict):
            raise WeComCryptoError("plaintext JSON is not an object")
        return data
    return _parse_plaintext_xml(stripped)


def _reply_plaintext_xml(to_user: str, from_user: str, content: str) -> str:
    return (
        "<xml>"
        f"<ToUserName><![CDATA[{to_user}]]></ToUserName>"
        f"<FromUserName><![CDATA[{from_user}]]></FromUserName>"
        f"<CreateTime>{int(time.time())}</CreateTime>"
        "<MsgType><![CDATA[text]]></MsgType>"
        f"<Content><![CDATA[{content}]]></Content>"
        "</xml>"
    )


def _encrypted_reply_response(reply_plaintext: str, nonce: str, receive_id: str | None = None) -> Response:
    timestamp = str(int(time.time()))
    reply_nonce = nonce or secrets.token_hex(8)
    encrypted = _encrypt_wecom(reply_plaintext, WECOM_ENCODING_AES_KEY, receive_id if receive_id is not None else WECOM_CORP_ID)
    signature = _sha1_signature(WECOM_TOKEN, timestamp, reply_nonce, encrypted)
    response_xml = (
        "<xml>"
        f"<Encrypt><![CDATA[{encrypted}]]></Encrypt>"
        f"<MsgSignature><![CDATA[{signature}]]></MsgSignature>"
        f"<TimeStamp>{timestamp}</TimeStamp>"
        f"<Nonce><![CDATA[{reply_nonce}]]></Nonce>"
        "</xml>"
    )
    return Response(content=response_xml, media_type="application/xml")


def _build_aibot_stream_payload(reply_text: str, stream_id: str | None = None, finish: bool = True) -> dict:
    return {
        "msgtype": "stream",
        "stream": {
            "id": stream_id or secrets.token_hex(8),
            "finish": finish,
            "content": reply_text,
        },
    }


def _http_json(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _http_post_json_any(url: str, payload: dict) -> tuple[int, str]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _send_aibot_stream_response(response_url: str, reply_text: str, stream_id: str | None = None) -> tuple[int, str]:
    payload = _build_aibot_stream_payload(reply_text, stream_id=stream_id, finish=True)
    return _http_post_json_any(response_url, payload)


def _get_access_token() -> str:
    if not WECOM_APP_SECRET:
        raise RuntimeError("WECOM_APP_SECRET is not configured")
    url = (
        "https://qyapi.weixin.qq.com/cgi-bin/gettoken?" +
        urllib.parse.urlencode({"corpid": WECOM_CORP_ID, "corpsecret": WECOM_APP_SECRET})
    )
    data = _http_json(url)
    if data.get("errcode") != 0:
        raise RuntimeError(f"gettoken failed: {data}")
    return data["access_token"]


def _sync_kf_messages(token: str, open_kfid: str) -> list[dict]:
    access_token = _get_access_token()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
    payload = {"token": token, "limit": 100, "open_kfid": open_kfid}
    data = _http_json(url, payload)
    if data.get("errcode") != 0:
        raise RuntimeError(f"kf/sync_msg failed: {data}")
    return data.get("msg_list", [])


def _send_kf_text(open_kfid: str, external_userid: str, content: str) -> dict:
    access_token = _get_access_token()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"
    payload = {
        "touser": external_userid,
        "open_kfid": open_kfid,
        "msgtype": "text",
        "text": {"content": content},
    }
    data = _http_json(url, payload)
    if data.get("errcode") != 0:
        raise RuntimeError(f"kf/send_msg failed: {data}")
    return data


def _extract_kf_text_messages(msg_list: list[dict]) -> list[dict]:
    extracted: list[KfTextMessage] = []
    for item in msg_list:
        msgtype = item.get("msgtype", "")
        text = item.get("text", {}) or {}
        content = text.get("content", "")
        external_userid = item.get("external_userid", "")
        open_kfid = item.get("open_kfid", "")
        msgid = item.get("msgid", "")
        if msgtype == "text" and content and external_userid and open_kfid and msgid:
            extracted.append(
                KfTextMessage(
                    msgid=msgid,
                    content=content,
                    external_userid=external_userid,
                    open_kfid=open_kfid,
                    origin=item,
                )
            )
    return extracted


def _load_seen_msgids() -> set[str]:
    try:
        raw = json.loads(SEEN_MSGIDS_PATH.read_text())
    except FileNotFoundError:
        return set()
    except Exception:
        logger.exception("failed to load seen msgids cache")
        return set()
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw if item}


def _save_seen_msgids(msgids: set[str]) -> None:
    trimmed = sorted(msgids)[-MAX_SEEN_MSGIDS:]
    SEEN_MSGIDS_PATH.write_text(json.dumps(trimmed))


def _filter_new_messages(messages: list[KfTextMessage]) -> list[KfTextMessage]:
    seen = _load_seen_msgids()
    new_messages = [item for item in messages if item.msgid not in seen]
    if not new_messages:
        return []
    latest_only = [new_messages[-1]]
    for item in new_messages:
        seen.add(item.msgid)
    _save_seen_msgids(seen)
    return latest_only


def _success_response() -> Response:
    return Response(status_code=200, content="success", media_type="text/plain")


def _get_required_query_param(request: Request, key: str) -> str:
    value = request.query_params.get(key, "")
    if not value:
        raise HTTPException(status_code=400, detail=f"Missing required query parameter: {key}")
    return value


def _get_wecom_query_params(request: Request, include_echostr: bool = False) -> tuple[str, str, str, str | None]:
    msg_signature = _get_required_query_param(request, "msg_signature")
    timestamp = _get_required_query_param(request, "timestamp")
    nonce = _get_required_query_param(request, "nonce")
    echostr = unquote(_get_required_query_param(request, "echostr")) if include_echostr else None
    return msg_signature, timestamp, nonce, echostr


def _ensure_valid_signature(msg_signature: str, timestamp: str, nonce: str, encrypted: str) -> None:
    expected_signature = _sha1_signature(WECOM_TOKEN, timestamp, nonce, encrypted)
    if expected_signature != msg_signature:
        raise HTTPException(status_code=403, detail="Invalid msg_signature")


def _extract_message_fields(message: dict) -> tuple[str, str, str, str, str]:
    msg_type = str(message.get("MsgType") or message.get("msgtype") or "")
    event = str(message.get("Event") or message.get("event") or "")
    content = str(message.get("Content") or "")
    from_user = str(message.get("FromUserName") or "")
    to_user = str(message.get("ToUserName") or "")

    if not content and isinstance(message.get("text"), dict):
        content = str(message["text"].get("content", ""))
    if not from_user and isinstance(message.get("from"), dict):
        from_user = str(message["from"].get("userid", ""))

    return msg_type, event, content, from_user, to_user


def _parse_callback_body(request_body: str) -> tuple[str, dict]:
    try:
        encrypted = _extract_encrypt(request_body)
    except WeComCryptoError as e:
        logger.exception("wecom POST body parse failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e)) from e

    try:
        plaintext = _decrypt_wecom(encrypted, WECOM_ENCODING_AES_KEY, WECOM_CORP_ID)
        logger.warning("wecom POST decrypt success plaintext=%s", plaintext)
    except WeComCryptoError as e:
        logger.exception("wecom POST decrypt failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e)) from e

    message = _parse_plaintext_message(plaintext)
    logger.warning("wecom plaintext message parsed=%s", message)
    return encrypted, message


def _handle_aibot_text_message(message: dict, nonce: str, content: str, reply_text: str) -> Response:
    response_url = str(message.get("response_url", "") or "")
    logger.warning("wecom replying with aibot stream for content=%s response_url=%s", content, response_url)
    if response_url:
        status_code, response_body = _send_aibot_stream_response(
            response_url,
            reply_text,
            stream_id=message.get("msgid"),
        )
        logger.warning(
            "wecom aibot response posted status_code=%s response_body=%s",
            status_code,
            response_body,
        )
        return _success_response()

    reply_plaintext = json.dumps(
        _build_aibot_stream_payload(reply_text, stream_id=message.get("msgid")),
        ensure_ascii=False,
    )
    return _encrypted_reply_response(reply_plaintext, nonce, receive_id="")


def _handle_standard_text_message(
    message: dict,
    nonce: str,
    content: str,
    from_user: str,
    to_user: str,
) -> Response:
    faq_match = match_faq(content)
    if faq_match is None:
        logger.warning("wecom standard text no faq match content=%s", content)
        return _success_response()
    reply_text = faq_match.entry.answer
    logger.warning(
        "wecom standard text matched faq_id=%s score=%.2f content=%s",
        faq_match.entry.id,
        faq_match.score,
        content,
    )
    if "aibotid" in message:
        return _handle_aibot_text_message(message, nonce, content, reply_text)

    reply_plaintext_xml = _reply_plaintext_xml(to_user=from_user, from_user=to_user, content=reply_text)
    logger.warning("wecom replying with legacy canned text for content=%s", content)
    return _encrypted_reply_response(reply_plaintext_xml, nonce)


def _handle_kf_event_message(message: dict) -> Response:
    sync_token = str(message.get("Token", ""))
    open_kfid = str(message.get("OpenKfId", ""))
    if not sync_token:
        logger.warning("wecom kf event missing sync token")
        return _success_response()

    try:
        msg_list = _sync_kf_messages(sync_token, open_kfid)
        logger.warning("wecom kf sync returned %s messages", len(msg_list))
        text_messages = _extract_kf_text_messages(msg_list)
        logger.warning("wecom kf extracted %s text messages", len(text_messages))
        new_messages = _filter_new_messages(text_messages)
        logger.warning("wecom kf new text messages %s", len(new_messages))
        for item in new_messages:
            faq_match = match_faq(item.content)
            if faq_match is None:
                logger.warning("wecom kf no faq match content=%s", item.content)
                continue
            reply_text = faq_match.entry.answer
            _send_kf_text(
                open_kfid=item.open_kfid or open_kfid,
                external_userid=item.external_userid,
                content=reply_text,
            )
            logger.warning(
                "wecom kf replied faq_id=%s external_userid=%s content=%s",
                faq_match.entry.id,
                item.external_userid,
                item.content,
            )
    except Exception as exc:
        logger.exception("wecom kf handling failed: %s", exc)

    return _success_response()


@router.get("/api/wecom/callback")
async def verify_wecom(request: Request):
    msg_signature, timestamp, nonce, echostr = _get_wecom_query_params(request, include_echostr=True)
    if echostr is None:
        raise HTTPException(status_code=400, detail="Missing required query parameter: echostr")
    _ensure_valid_signature(msg_signature, timestamp, nonce, echostr)
    try:
        plaintext = _decrypt_wecom(echostr, WECOM_ENCODING_AES_KEY, WECOM_CORP_ID)
        logger.warning("wecom GET decrypt success plaintext=%s", plaintext)
    except WeComCryptoError as e:
        logger.exception("wecom GET decrypt failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e)) from e
    return PlainTextResponse(content=plaintext)


@router.post("/api/wecom/callback")
async def receive_wecom(request: Request):
    msg_signature, timestamp, nonce, _ = _get_wecom_query_params(request)
    body_text = (await request.body()).decode("utf-8")
    logger.warning(
        "wecom POST received content_type=%s query=%s raw_body=%s",
        request.headers.get("content-type", ""),
        dict(request.query_params),
        body_text,
    )
    encrypted, message = _parse_callback_body(body_text)
    _ensure_valid_signature(msg_signature, timestamp, nonce, encrypted)
    msg_type, event, content, from_user, to_user = _extract_message_fields(message)
    logger.warning(
        "wecom message parsed msg_type=%s event=%s from_user=%s to_user=%s content=%s",
        msg_type,
        event,
        from_user,
        to_user,
        content,
    )

    if msg_type == "text":
        return _handle_standard_text_message(message, nonce, content, from_user, to_user)

    if msg_type == "event" and event == "kf_msg_or_event":
        return _handle_kf_event_message(message)

    return _success_response()
