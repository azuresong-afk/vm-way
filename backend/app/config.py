"""Настройки из окружения (.env)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="VM_", extra="ignore")

    database_url: str = "sqlite:///./vm.db"
    # Ключ подписи токенов (HMAC) и ключ шифрования секретов (AES-GCM, 32 байта в base64).
    secret_key: str = ""
    encryption_key: str = ""
    token_ttl_minutes: int = 480
    auth_mode: str = "local"  # local | platform (этап 3)
    # Защита от перебора пароля: сколько неудачных входов за окно допускается для пары
    # «учётная запись + адрес», для одного адреса (любые имена) и для учётной записи (любые адреса).
    login_window_minutes: int = 15
    login_max_failures: int = 5
    login_max_failures_ip: int = 30
    login_max_failures_account: int = 20
    product_version: str = "0.1.0"
    # Базовый адрес веб-интерфейса «Сканера» для ссылок «Открыть в Сканере».
    scanner_web_url: str = ""
    # Первый администратор (создаётся при старте, если пользователей нет).
    admin_username: str = "admin"
    admin_password: str = ""
    # Демо-режим: проект, источник mock://demo и пользователи с паролем demo_password.
    demo: bool = False
    demo_password: str = ""
    # Источники mock:// (встроенный мок «Сканера»): только для демо-стенда и тестов.
    allow_mock_sources: bool = False
    # Пул коротких задач (импорт, опрос, шаги повторных проверок) и пул долгих (раскатки).
    jobs_workers: int = 4
    jobs_long_workers: int = 4
    # Как часто планировщик запускает задачи, у которых подошёл срок.
    jobs_tick_seconds: float = 1.0
    # Пауза перед первым повтором после временной ошибки; каждый следующий — вчетверо дольше.
    jobs_retry_seconds: float = 30.0
    # Сроки хранения, дней (0 — не чистить): завершённые задачи, доставленные и недоставленные события outbox.
    jobs_retention_days: int = 30
    outbox_retention_days: int = 30
    outbox_undelivered_retention_days: int = 90
    # Задачи исполняются сразу в запросе (тесты).
    jobs_inline: bool = False
    poll_enabled: bool = True
    verify_poll_seconds: float = 5.0
    verify_timeout_minutes: int = 240
    # Раскатки (задача 2.4): сколько ждать хост после перезагрузки и как часто стучаться.
    rollout_reboot_timeout_seconds: int = 600
    rollout_reconnect_seconds: float = 10.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
