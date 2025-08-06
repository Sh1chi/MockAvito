"""
Вынесена в отдельный файл, чтобы не дублировать код по всем роутерам.
"""
import time, logging
from fastapi import Header, HTTPException
from tokens import TOKENS   # существующий словарь refresh → (access, exp)

log = logging.getLogger("MockAvito.auth_utils")

def check_bearer_token(Authorization: str = Header(...)) -> None:
    if not Authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")

    token = Authorization.split()[1]
    is_valid = any(token == v[0] and v[1] > time.time() for v in TOKENS.values())
    if not is_valid:
        raise HTTPException(401, "Invalid or expired token")
    else:
        log.info("Token valid")

