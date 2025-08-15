"""
Mock-реализация /messenger/* эндпоинтов Avito:
- список чатов,
- подписка/отписка на вебхук,
- симуляция входящих сообщений,
- просмотр сообщений чата и информации о чате.
"""

import time, uuid, json, hmac, hashlib, base64, logging, httpx, asyncpg
from typing import Dict, Optional, Sequence
from fastapi import APIRouter, HTTPException, Form, Query, Depends

from auth_utils import check_bearer_token
import db  # pool инициализируется в main.install_pool

router = APIRouter()
log = logging.getLogger("MockAvito.messenger")

# Подписчики вебхуков: sub_id → {url, secret, user_id}
SUBSCRIBERS: Dict[str, dict] = {}


def _now() -> int:
    """Текущее время в секундах UNIX."""
    return int(time.time())


async def _chat_pk_by_avito_id(conn: asyncpg.Connection, avito_chat_id: str) -> Optional[int]:
    """Возвращает внутренний PK чата по внешнему avito_chat_id или None."""
    row = await conn.fetchrow(
        "SELECT id FROM mock_avito.chats WHERE avito_chat_id = $1",
        avito_chat_id,
    )
    return int(row["id"]) if row else None


async def _ensure_chat(conn: asyncpg.Connection, avito_chat_id: str, users: Sequence[int] | None = None) -> int:
    """
    Возвращает PK чата, создавая его при необходимости.
    При создании можно сразу указать список участников (user_id).
    """
    pk = await _chat_pk_by_avito_id(conn, avito_chat_id)
    if pk:
        return pk
    users_json = None
    if users:
        # asyncpg умеет конвертить list[int] → bigint[]
        users_json = await conn.fetchval("SELECT to_jsonb($1::bigint[])", users)
    row = await conn.fetchrow(
        """
        INSERT INTO mock_avito.chats (avito_chat_id, context_type, context_value, users, created_ts, updated_ts)
        VALUES ($1, 'generic', '{}'::jsonb, COALESCE($2, '[]'::jsonb), NOW(), NOW())
        RETURNING id
        """,
        avito_chat_id,
        users_json,
    )
    return int(row["id"])


async def _check_membership(conn: asyncpg.Connection, chat_pk: int, user_id: int) -> None:
    """"
    Возвращает список чатов пользователя (v2).
    """
    ok = await conn.fetchval(
        """
        SELECT EXISTS (
          SELECT 1
          FROM mock_avito.chats c
          WHERE c.id = $1
            AND c.users @> jsonb_build_array($2::bigint)
        )
        """,
        chat_pk,
        user_id,
    )
    if not ok:
        raise HTTPException(403, "token/user mismatch for this chat")


def _sign(secret: str | bytes, body: bytes) -> str:
    """Формирует HMAC-SHA256 подпись тела body по секрету secret."""
    key = secret.encode() if isinstance(secret, str) else secret
    mac = hmac.new(key, body, hashlib.sha256).digest()
    return base64.b64encode(mac).decode()


@router.post("/messenger/v3/webhook")
async def subscribe_webhook(body: dict):
    """
    Регистрирует вебхук в памяти мока.
    Параметры:
      - url (str) — куда отправлять события;
      - secret (str, опционально) — ключ для подписи;
      - user_id (int) — чьи события слать.
    """
    url = body.get("url")
    if not url:
        raise HTTPException(400, "'url' required")

    user_id = body.get("user_id")
    if user_id is None:
        raise HTTPException(400, "'user_id' required")

    sub_id = uuid.uuid4().hex
    SUBSCRIBERS[sub_id] = {
        "url": str(url),
        "secret": str(body.get("secret", "changeme")),
        "user_id": int(user_id),
    }
    log.info("Webhook subscribed: %s → %s (user_id=%s)", sub_id, url, user_id)
    return {"id": sub_id, "ok": True}


@router.delete("/messenger/v3/webhook/{sub_id}")
async def unsubscribe_webhook(sub_id: str):
    """Удаляет подписку по её sub_id."""
    if SUBSCRIBERS.pop(sub_id, None) is None:
        raise HTTPException(404, "no such subscription")
    log.info("Webhook %s removed", sub_id)
    return {"ok": True}


async def _broadcast(event: dict):
    """
    Рассылает событие всем подписанным вебхукам.
    Перед отправкой подставляет user_id подписчика в payload/value.
    """
    if not SUBSCRIBERS:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        for sid, cfg in SUBSCRIBERS.items():
            # не мутируем исходный объект
            payload = json.loads(json.dumps(event, ensure_ascii=False))
            payload["payload"]["value"]["user_id"] = cfg["user_id"]
            body = json.dumps(payload, ensure_ascii=False).encode()
            sig = _sign(cfg["secret"], body)
            try:
                resp = await client.post(
                    cfg["url"],
                    content=body,
                    headers={"Content-Type": "application/json", "X-Hook-Signature": sig},
                )
                log.info("→ webhook %s %s %s", sid, resp.status_code, resp.text[:200])
            except Exception as exc:
                log.warning("Webhook %s failed: %s", sid, exc)


@router.post("/messenger/v3/_simulate_inbound")
async def simulate_inbound(
    text: str = Form(...),
    chat_id: str = Form("chat-001"),
    author_id: int = Form(555),
):
    """
    Создаёт входящее (in) сообщение в указанном чате и рассылает вебхуки.
    """
    assert db.pool, "DB pool is not initialised – did you call db.install_pool(app)?"

    now = _now()
    avito_msg_id = f"m-{uuid.uuid4().hex[:12]}"

    async with db.pool.acquire() as conn:  # type: ignore[attr-defined]
        chat_pk = await _ensure_chat(conn, chat_id)
        await conn.execute(
            """
            INSERT INTO mock_avito.messages
              (avito_msg_id, chat_id, author_id, direction, content, msg_type, created_ts, is_read)
            VALUES
              ($1, $2, $3, 'in', jsonb_build_object('text', $4::text), 'text', to_timestamp($5), false)
            """,
            avito_msg_id,
            chat_pk,
            author_id,
            text,
            now,
        )
        await conn.execute(
            "UPDATE mock_avito.chats SET updated_ts = to_timestamp($2) WHERE id = $1",
            chat_pk,
            now,
        )

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
                "id": avito_msg_id,
                "item_id": None,
                "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "read": None,
                "type": "text",
                # user_id добавляется при _broadcast
            },
        },
    }
    await _broadcast(event)
    return {"ok": True, "avito_msg_id": avito_msg_id}


@router.get(
    "/messenger/v3/accounts/{user_id}/chats/{chat_id}/messages/",
    summary="List chat messages (Mock)",
)
async def list_messages(
    user_id: int,
    chat_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    auth_user_id: int = Depends(check_bearer_token),
):
    """
    Возвращает список сообщений чата (v3).
    Проверяет, что токен принадлежит user_id и что он участник чата.
    """
    if user_id != auth_user_id:
        raise HTTPException(403, "token/user mismatch")

    assert db.pool, "DB pool is not initialised – did you call db.install_pool(app)?"

    async with db.pool.acquire() as conn:  # type: ignore[attr-defined]
        chat_pk = await _chat_pk_by_avito_id(conn, chat_id)
        if not chat_pk:
            raise HTTPException(404, "chat not found")
        await _check_membership(conn, chat_pk, auth_user_id)

        rows = await conn.fetch(
            """
            SELECT
                m.avito_msg_id                           AS id,
                m.author_id,
                m.content,
                EXTRACT(EPOCH FROM m.created_ts)::BIGINT AS created,
                m.direction,
                m.is_read,
                m.quote,
                EXTRACT(EPOCH FROM m.read_ts)::BIGINT    AS read,
                m.msg_type                               AS type
            FROM   mock_avito.messages  m
            WHERE  m.chat_id = $1
            ORDER  BY m.created_ts DESC
            OFFSET $2
            LIMIT  $3
            """,
            chat_pk,
            offset,
            limit,
        )

    def _clean(record):
        d = dict(record)
        return {k: v for k, v in d.items() if v is not None}

    return {"messages": [_clean(r) for r in rows]}


@router.get(
    "/messenger/v2/accounts/{user_id}/chats/{chat_id}",
    summary="Chat info + last_message (Mock Avito v2)",
)
async def get_chat_info(
    user_id: int,
    chat_id: str,
    auth_user_id: int = Depends(check_bearer_token),
):
    """
    Информация о чате + последнее сообщение (в формате Avito v2).
    """
    if user_id != auth_user_id:
        raise HTTPException(403, "token/user mismatch")

    assert db.pool, "DB pool not initialised – did you forget install_pool(app)?"

    async with db.pool.acquire() as conn:  # type: ignore[attr-defined]
        chat = await conn.fetchrow(
            """
            SELECT
                id,  -- internal PK
                avito_chat_id            AS chat_id,
                context_type,
                context_value,
                EXTRACT(EPOCH FROM created_ts)::BIGINT AS created,
                EXTRACT(EPOCH FROM updated_ts)::BIGINT AS updated,
                users
            FROM mock_avito.chats
            WHERE avito_chat_id = $1
            """,
            chat_id,
        )
        if not chat:
            raise HTTPException(404, "chat not found")

        await _check_membership(conn, int(chat["id"]), auth_user_id)

        last = await conn.fetchrow(
            """
            SELECT
                avito_msg_id                           AS id,
                author_id,
                content,
                EXTRACT(EPOCH FROM created_ts)::BIGINT AS created,
                direction,
                msg_type                                AS type
            FROM mock_avito.messages
            WHERE chat_id = $1
            ORDER BY created_ts DESC
            LIMIT 1
            """,
            int(chat["id"]),
        )

    def _clean(record):
        d = dict(record)
        return {k: v for k, v in d.items() if v is not None}

    return {
        "context": {
            "type": chat["context_type"],
            "value": chat["context_value"],
        },
        "created": chat["created"],
        "id": chat["chat_id"],
        "updated": chat["updated"],
        "users": chat["users"],
        "last_message": _clean(last) if last else None,
    }
