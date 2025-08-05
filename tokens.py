"""
/token endpoint и вся логика хранения/обновления токенов.
"""

import time, uuid, logging
from typing import Dict
from fastapi import APIRouter, Form, HTTPException

router = APIRouter()
TOKEN_LIFETIME = 3600  # 1 час
TOKENS: Dict[str, tuple[str, int]] = {}   # refresh → (access, expires_at)

log = logging.getLogger("MockAvito.tokens")


def _gen_token() -> str:
    """32-символьный случайный hex‐токен."""
    return uuid.uuid4().hex


@router.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str | None = Form(None),
):
    """
    Эмулирует поведение Avito /token endpoint:
    - authorization_code → выдаёт новые access/refresh токены;
    - refresh_token → обновляет пару токенов;
    - другие grant_type → ошибка.
    """
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(400, "'code' required for authorization_code flow")

        access = _gen_token()
        refresh = _gen_token()
        TOKENS[refresh] = (access, int(time.time()) + TOKEN_LIFETIME)
        log.info(f"Exchanged code '{code}' for access_token '{access}' and refresh_token '{refresh}'")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME,
        }

    if grant_type == "refresh_token":
        if not refresh_token or refresh_token not in TOKENS:
            log.warning(f"Invalid refresh_token '{refresh_token}'")
            raise HTTPException(400, "invalid_grant")

        access = _gen_token()
        new_refresh = _gen_token()
        TOKENS[new_refresh] = (access, int(time.time()) + TOKEN_LIFETIME)
        del TOKENS[refresh_token]
        log.info(f"Refreshed token. New access_token: '{access}', new refresh_token: '{new_refresh}'")
        return {
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME,
        }

    log.error(f"Unsupported grant_type '{grant_type}'")
    raise HTTPException(400, "unsupported_grant_type")
