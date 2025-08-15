"""
Mock-реализация Avito /token endpoint и логика хранения/обновления токенов.
Хранение — в памяти процесса, без БД.
"""

import time, uuid, logging
from typing import Dict, Optional
from fastapi import APIRouter, Form, HTTPException

import config

router = APIRouter()
TOKEN_LIFETIME = 86400  # 24 часа

# refresh → {access, exp, user_id}
TOKENS: Dict[str, Dict[str, object]] = {}
# access → {exp, user_id, grant}
ACCESS_INDEX: Dict[str, Dict[str, object]] = {}
# code → user_id (эмуляция шага consent)
CODE_INDEX: Dict[str, int] = {}

log = logging.getLogger("MockAvito.tokens")


def _gen_token() -> str:
    """Генерирует случайный 32-символьный hex-токен."""
    return uuid.uuid4().hex


def _issue_pair(user_id: int) -> dict:
    """
    Создаёт новую пару access/refresh токенов для пользователя.
    Записывает их в память с временем истечения.
    """
    access = _gen_token()
    refresh = _gen_token()
    exp = int(time.time()) + TOKEN_LIFETIME
    TOKENS[refresh] = {"access": access, "exp": exp, "user_id": user_id}
    ACCESS_INDEX[access] = {"exp": exp, "user_id": user_id, "grant": "authorization_code"}
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": TOKEN_LIFETIME,
    }


def get_user_id_by_access(access: str) -> Optional[dict]:
    """
    Возвращает словарь с информацией по access_token
    или None, если токен не найден/просрочен.
    """
    rec = ACCESS_INDEX.get(access)
    if not rec:
        return None
    if rec["exp"] <= time.time():
        return None
    return rec


@router.post("/oauth/mock_authorize")
async def mock_authorize(user_id: int = Form(...)) -> dict:
    """
    Эмулирует шаг consent в OAuth:
    возвращает одноразовый code для указанного user_id.
    """
    code = _gen_token()
    CODE_INDEX[code] = user_id
    return {"code": code}


@router.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str | None = Form(None),
    scope: str | None = Form(None),
):
    """
    Эмулирует поведение Avito /token:
      - authorization_code → выдаёт access/refresh токены на 24ч;
      - refresh_token → обновляет пару токенов;
      - client_credentials → выдаёт только access на 24ч.
    """
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(400, "'code' required for authorization_code flow")
        if code in CODE_INDEX:
            user_id = CODE_INDEX.pop(code)
        else:
            # позволяем тестировать, если code — это число
            try:
                user_id = int(code)
            except Exception:
                user_id = config.OWNER_ID
        res = _issue_pair(user_id)
        log.info("auth_code → access=%s refresh=%s for user_id=%s", res["access_token"], res["refresh_token"], user_id)
        return res

    if grant_type == "refresh_token":
        if not refresh_token or refresh_token not in TOKENS:
            raise HTTPException(400, "invalid_grant")
        old = TOKENS.pop(refresh_token)
        user_id = int(old["user_id"])
        res = _issue_pair(user_id)
        log.info("refresh → access=%s refresh=%s for user_id=%s", res["access_token"], res["refresh_token"], user_id)
        return res

    if grant_type == "client_credentials":
        access = _gen_token()
        exp = int(time.time()) + TOKEN_LIFETIME
        ACCESS_INDEX[access] = {"exp": exp, "user_id": config.OWNER_ID, "grant": "client_credentials"}
        log.info("client_credentials → access=%s user_id=%s", access, config.OWNER_ID)
        return {
            "access_token": access,
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME,
        }

    raise HTTPException(400, "unsupported_grant_type")
