"""
asyncpg-пул, доступный из любого mock-роутера.
"""
import asyncpg, logging
from fastapi import FastAPI

from config import DATABASE_URL

pool: asyncpg.Pool | None = None   # будет заполнен при старте приложения

log = logging.getLogger("MockAvito.DB")


def install_pool(app: FastAPI) -> None:
    """Подключить события startup/shutdown к FastAPI-приложению."""
    @app.on_event("startup")
    async def _open_pool() -> None:
        global pool
        pool = await asyncpg.create_pool(DATABASE_URL,
                                         min_size=1,
                                         max_size=5,
                                         )
        log.info("Database connection established")

    @app.on_event("shutdown")
    async def _close_pool() -> None:
        await pool.close()         # type: ignore[arg-type]
        log.info("Database connection closed")
