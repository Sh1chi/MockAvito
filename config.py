"""
Конфиг Mock-API
"""
import os
from dotenv import load_dotenv

# грузим .env, если есть рядом с mock-кодом
load_dotenv(".env")

# DSN базы; по-умолчанию – локальный postgres
DATABASE_URL: str = os.getenv(
    "MOCK_AVITO_DB"
)

# — при желании можно добавить DEBUG-флаги и т.п. —
