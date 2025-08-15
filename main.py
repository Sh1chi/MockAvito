"""
Точка входа: создаёт FastAPI-app, подключает роутеры и логирование.
"""

from fastapi import FastAPI, Request

from logging_cfg import setup
from tokens import router as tokens_router
from messenger import router as messenger_router
from accounts import router as accounts_router
from db import install_pool

log = setup()

app = FastAPI(title="Mock Avito API")
install_pool(app)

# Подключаем mock-роутеры: OAuth и Messenger API
app.include_router(tokens_router)
app.include_router(messenger_router)
app.include_router(accounts_router)


@app.middleware("http")
async def _log_requests(request: Request, call_next):
    """
    Middleware для логирования всех HTTP-запросов mock-сервиса.
    """
    log.info("--> %s %s", request.method, request.url.path)
    resp = await call_next(request)
    log.info("<-- %s %s", resp.status_code, request.url.path)
    return resp
