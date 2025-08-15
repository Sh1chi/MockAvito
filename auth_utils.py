import logging
from fastapi import Header, HTTPException

from tokens import get_user_id_by_access

log = logging.getLogger("MockAvito.auth_utils")

def check_bearer_token(Authorization: str = Header(...)) -> int:
    """
    Проверяет Bearer-токен в заголовке Authorization и возвращает user_id.

    Выбрасывает HTTP 401:
    - если заголовок отсутствует или имеет неверный формат,
    - если токен не найден или просрочен.
    """
    if not Authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    token = Authorization.split()[1]
    rec = get_user_id_by_access(token)
    if not rec:
        raise HTTPException(401, "Invalid or expired token")
    return int(rec["user_id"])

