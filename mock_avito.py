"""Mock Avito OAuth & Messenger API for local testing
Run with:
    uvicorn mock_avito:app --port 9000 --reload
Then point TOKEN_URL in your main service to http://localhost:9000/token
"""

import time
import uuid
from fastapi import FastAPI, Form, HTTPException, Header, Request
import logging

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
