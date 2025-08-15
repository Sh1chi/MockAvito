"""
Конфиг Mock-API
"""
import os
from dotenv import load_dotenv

# грузим .env, если есть рядом с mock-кодом
load_dotenv(".env")

# DSN базы; по-умолчанию – локальный postgres (если нужен)
DATABASE_URL: str | None = os.getenv("MOCK_AVITO_DB")

# Данные «владельца приложения» — используются для client_credentials и по умолчанию.
OWNER_ID: int = int(os.getenv("MOCK_OWNER_ID", "94235311"))
OWNER_NAME: str = os.getenv("MOCK_OWNER_NAME", "Шевцов Артем")
OWNER_EMAIL: str = os.getenv("MOCK_OWNER_EMAIL", "Shevcov_2k4_2@mail.ru")
OWNER_PHONE: str = os.getenv("MOCK_OWNER_PHONE", "89588486307")
OWNER_PROFILE_URL: str = os.getenv(
    "MOCK_OWNER_PROFILE_URL",
    f"https://avito.ru/user/mock/{OWNER_ID}/profile"
)