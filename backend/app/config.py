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
    product_version: str = "0.1.0"
    # Базовый адрес веб-интерфейса «Сканера» для ссылок «Открыть в Сканере».
    scanner_web_url: str = ""
    # Первый администратор (создаётся при старте, если пользователей нет).
    admin_username: str = "admin"
    admin_password: str = ""
    # Демо-режим: проект, источник mock://demo и пользователи с паролем demo_password.
    demo: bool = False
    demo_password: str = ""
    jobs_workers: int = 4
    poll_enabled: bool = True
    verify_poll_seconds: float = 5.0
    verify_timeout_minutes: int = 240


@lru_cache
def get_settings() -> Settings:
    return Settings()
