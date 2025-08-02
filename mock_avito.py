"""Mock Avito OAuth & Messenger API for local testing
Run with:
    uvicorn mock_avito:app --port 9000 --reload
Then point TOKEN_URL in your main service to http://localhost:9000/token
"""

import time
import uuid
from fastapi import FastAPI, Form, HTTPException, Header, Request
import logging
import hmac, hashlib, base64, httpx
import json

app = FastAPI(title="Mock Avito API")

# In-memory store: refresh_token -> (access_token, expires_at)
TOKENS = {}

TOKEN_LIFETIME = 3600  # seconds

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
logger = logging.getLogger("mock_avito")

def _gen_token() -> str:
    """Create a random 32-char hex string."""
    return uuid.uuid4().hex

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str | None = Form(None),
):
    """Imitates Avito OAuth 2.0 token endpoint."""

    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(400, "'code' required for authorization_code flow")

        access = _gen_token()
        refresh = _gen_token()
        TOKENS[refresh] = (access, int(time.time()) + TOKEN_LIFETIME)
        logger.info(f"Exchanged code '{code}' for access_token '{access}' and refresh_token '{refresh}'")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME,
        }

    if grant_type == "refresh_token":
        if not refresh_token or refresh_token not in TOKENS:
            logger.warning(f"Invalid refresh_token '{refresh_token}'")
            raise HTTPException(400, "invalid_grant")

        access = _gen_token()
        new_refresh = _gen_token()
        TOKENS[new_refresh] = (access, int(time.time()) + TOKEN_LIFETIME)
        del TOKENS[refresh_token]
        logger.info(f"Refreshed token. New access_token: '{access}', new refresh_token: '{new_refresh}'")
        return {
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME,
        }

    logger.error(f"Unsupported grant_type '{grant_type}'")
    raise HTTPException(400, "unsupported_grant_type")


@app.get("/messenger/v2/chats")
async def list_chats(Authorization: str = Header(...)):
    """Very lightweight mock for GET /messenger/v2/chats."""
    logger.info(f"Checking access for token '{Authorization}'")
    if not Authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")

    token = Authorization.split()[1]
    valid = any(token == v[0] and v[1] > time.time() for v in TOKENS.values())
    if not valid:
        logger.warning(f"Unauthorized access with token '{token}'")
        raise HTTPException(401, "Invalid or expired token")

    logger.info(f"Authorized request with token '{token}', returning mock chats")
    return {
        "chats": [
            {"chat_id": 1, "title": "Mock chat #1"},
            {"chat_id": 2, "title": "Mock chat #2"},
        ]
    }


# ---------------------------------------------------------------------------
# Web-hook subscription & test events
# ---------------------------------------------------------------------------

SUBSCRIBERS: dict[str, dict] = {}      # id -> {url, secret}

def _sign(body: bytes, secret: str) -> str:
    return base64.b64encode(
        hmac.new(secret.encode(), body, hashlib.sha256).digest()
    ).decode()

@app.post("/messenger/v3/webhook")
async def subscribe_webhook(data: dict):
    """
    Официальный путь у Avito: POST /messenger/v3/webhook
    Тело: {"url": "...", "secret": "optional"}
    """
    url = data.get("url")
    if not url:
        raise HTTPException(400, "'url' required")

    sub_id = uuid.uuid4().hex
    SUBSCRIBERS[sub_id] = {"url": url, "secret": data.get("secret", "changeme")}
    logger.info("Webhook subscribed: %s → %s", sub_id, url)
    return {"id": sub_id, "ok": True}

@app.delete("/messenger/v3/webhook/{sub_id}")
async def unsubscribe_webhook(sub_id: str):
    if SUBSCRIBERS.pop(sub_id, None) is None:
        raise HTTPException(404, "no such subscription")
    logger.info("Webhook %s removed", sub_id)
    return {"ok": True}

async def _broadcast(event: dict):
    """Шлём одно и то же событие всем подписчикам."""
    async with httpx.AsyncClient(timeout=10) as client:
        for sid, cfg in SUBSCRIBERS.items():
            body = json.dumps(event).encode()
            sig  = _sign(body, cfg["secret"])
            try:
                r = await client.post(
                    cfg["url"],
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Hook-Signature": sig,
                    },
                )
                logger.info("→ webhook %s %s %s", sid, r.status_code, r.text[:200])
            except Exception as exc:
                logger.warning("Webhook %s failed: %s", sid, exc)

@app.post("/messenger/v3/_simulate_inbound")
async def simulate_inbound(text: str = Form(...), chat_id: int = Form(1)):
    """Локальный помощник: делает «входящее сообщение» и шлёт Web-hook."""
    event = {
        "id": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "version": "3",
        "payload": {
            "message": {
                "chat_id": chat_id,
                "text": text,
            }
        },
    }
    await _broadcast(event)
    return {"sent": True, "subscribers": len(SUBSCRIBERS)}
