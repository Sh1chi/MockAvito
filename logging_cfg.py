"""
Настройка логгирования для mock-сервиса.
"""
import logging, sys

def setup() -> logging.Logger:
    """
    Инициализирует логгер с выводом в stdout.
    Используется во всех частях мок‑сервиса.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    return logging.getLogger("MockAvito")
