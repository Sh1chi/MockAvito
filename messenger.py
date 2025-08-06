"""
/messenger/* эндпоинты: чаты, подписка на веб-хук, тестовый генератор inbound-сообщений.
"""

import time, uuid, json, hmac, hashlib, base64, httpx, logging
from typing import Dict
from fastapi import APIRouter, HTTPException, Header, Form, Query, Depends

from auth_utils import check_bearer_token
from db import pool                       # уже инициализируется при startup
from tokens import TOKENS

router  = APIRouter()
log = logging.getLogger("MockAvito.messenger")

# Подписчики вебхуков: sub_id → {url, secret, user_id}
SUBSCRIBERS: Dict[str, dict] = {}


@router.get("/messenger/v2/chats")
async def list_chats(Authorization: str = Header(...)):
    """
    Эмулирует Avito-эндпоинт получения списка чатов.
    Проверяет access_token, возвращает фиктивные чаты.
    """
    log.info(f"Checking access for token '{Authorization}'")
    if not Authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")

    token  = Authorization.split()[1]
    valid  = any(token == v[0] and v[1] > time.time() for v in TOKENS.values())
    if not valid:
        log.warning(f"Unauthorized access with token '{token}'")
        raise HTTPException(401, "Invalid or expired token")

    log.warning(f"Unauthorized access with token '{token}'")
    return {"chats": [
        {"chat_id": 1, "title": "Mock chat #1"},
        {"chat_id": 2, "title": "Mock chat #2"},
    ]}


def _sign(secret: str | bytes, body: bytes) -> str:
    """
    Генерирует HMAC-SHA256 подпись и возвращает её в формате Base64.
    Используется для заголовка X-Hook-Signature.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode()
    else:
        secret_bytes = secret
    digest = hmac.new(secret_bytes, body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


@router.post("/messenger/v3/webhook")
async def subscribe_webhook(body: dict):
    """
    Эмулирует регистрацию вебхука.
    Сохраняет URL, секрет и user_id в память.
    """
    url = body.get("url")
    if not url:
        raise HTTPException(400, "'url' required")

    sub_id = uuid.uuid4().hex
    SUBSCRIBERS[sub_id] = {
        "url": url,
        "secret": body.get("secret", "changeme"),
        "user_id": int(body.get("user_id", 0)),
    }
    log.info("Webhook subscribed: %s → %s", sub_id, url)
    return {"id": sub_id, "ok": True}


@router.delete("/messenger/v3/webhook/{sub_id}")
async def unsubscribe_webhook(sub_id: str):
    """
    Удаляет подписку по ID. Возвращает 404, если такой нет.
    """
    if SUBSCRIBERS.pop(sub_id, None) is None:
        raise HTTPException(404, "no such subscription")
    log.info("Webhook %s removed", sub_id)
    return {"ok": True}


async def _broadcast(event: dict):
    """
    Рассылает одно и то же событие всем зарегистрированным подписчикам.
    Автоматически добавляет user_id в payload.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        for sid, cfg in SUBSCRIBERS.items():
            # Вписываем user_id (идентификатор продавца, «кому принадлежит» webhook)
            event["payload"]["value"]["user_id"] = cfg["user_id"]
            data = json.dumps(event).encode()
            sig  = _sign(cfg["secret"], data)
            try:
                r = await client.post(
                    cfg["url"],
                    content=data,
                    headers={
                        "Content-Type": "application/json",
                        "X-Hook-Signature": sig,
                    },
                )
                log.info("→ webhook %s %s %s", sid, r.status_code, r.text[:120])
            except Exception as exc:
                log.warning("Webhook %s failed: %s", sid, exc)


@router.post("/messenger/v3/_simulate_inbound")
async def simulate_inbound(
    text: str = Form(...),
    chat_id: int = Form(1),
    author_id: int = Form(555),
):
    """
    Генерирует фиктивное входящее сообщение от клиента.
    Отправляется всем подписчикам как webhook-событие.
    """
    now = int(time.time())
    event = {
        "id": uuid.uuid4().hex,
        "timestamp": now,
        "version": "3",
        "payload": {
            "type": "message",
            "value": {
                "author_id": author_id,
                "chat_id": chat_id,
                "chat_type": "u2i",
                "content": {"text": text},
                "created": now,
                "id": uuid.uuid4().hex,
                "item_id": None,
                "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "read": None,
                "type": "text",
                # user_id
            },
        },
    }
    await _broadcast(event)
    return {"sent": True, "subscribers": len(SUBSCRIBERS)}


@router.get(
    "/messenger/v3/accounts/{user_id}/chats/{chat_id}/messages/",
    summary="List chat messages (Mock)",
)
async def list_messages(
    user_id: int,
    chat_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _token_ok: None = Depends(check_bearer_token),
):
    """
    Возвращает сообщения чата в формате Avito v3:
    последние сверху, время – epoch-секунды.
    """
    assert pool, "DB pool is not initialised – did you call db.install_pool(app)?"

    sql = """
    SELECT
        m.avito_msg_id                             AS id,
        m.author_id,
        m.content,
        EXTRACT(EPOCH FROM m.created_ts)::BIGINT   AS created,
        m.direction,
        m.is_read,
        m.quote,
        EXTRACT(EPOCH FROM m.read_ts)::BIGINT      AS read,
        m.msg_type                                 AS type
    FROM   mock_avito.messages  m
    JOIN   mock_avito.chats     c ON c.id = m.chat_id
    WHERE  c.avito_chat_id = $1
    ORDER  BY m.created_ts DESC
    LIMIT  $2 OFFSET $3;
    """

    async with pool.acquire() as conn:        # type: ignore[attr-defined]
        rows = await conn.fetch(sql, chat_id, limit, offset)

    # Убираем None-поля, Avito их просто не присылает
    def _clean(record):
        d = dict(record)
        return {k: v for k, v in d.items() if v is not None}

    return [_clean(r) for r in rows]