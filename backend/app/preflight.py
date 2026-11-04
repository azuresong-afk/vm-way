"""Проверка настроек перед запуском контейнера (docker/entrypoint.sh).

Пустые, шаблонные (CHANGE_ME) или негодные секреты останавливают старт с понятной
причиной в логе — вместо падения на первом запросе или работы со слабым ключом.

    python -m app.preflight
"""

import base64
import binascii
import sys

from app.config import Settings, get_settings

PLACEHOLDER = "CHANGE_ME"
MIN_PASSWORD = 10  # как у паролей пользователей (app/api/users.py)


def check(s: Settings) -> tuple[list[str], list[str]]:
    """Ошибки (старт невозможен) и предупреждения."""
    errors: list[str] = []
    warnings: list[str] = []

    if not s.secret_key or PLACEHOLDER in s.secret_key:
        errors.append("VM_SECRET_KEY не задан. Сгенерируйте: scripts/gen-env.sh или secrets.token_urlsafe(48)")
    elif len(s.secret_key) < 32:
        errors.append("VM_SECRET_KEY короче 32 символов — подпись токенов будет слабой")

    if not s.encryption_key or PLACEHOLDER in s.encryption_key:
        errors.append("VM_ENCRYPTION_KEY не задан. Сгенерируйте: base64 от 32 случайных байт")
    else:
        try:
            key = base64.b64decode(s.encryption_key, validate=True)
        except (binascii.Error, ValueError):
            key = b""
        if len(key) != 32:
            errors.append("VM_ENCRYPTION_KEY должен быть 32 байта в base64")

    if s.admin_password and (PLACEHOLDER in s.admin_password or len(s.admin_password) < MIN_PASSWORD):
        errors.append(f"VM_ADMIN_PASSWORD шаблонный или короче {MIN_PASSWORD} символов")
    if not s.admin_password:
        warnings.append("VM_ADMIN_PASSWORD пуст: если пользователей ещё нет, войти будет некому")

    if s.demo:
        if not s.demo_password or PLACEHOLDER in s.demo_password or len(s.demo_password) < MIN_PASSWORD:
            errors.append(f"VM_DEMO=1, а VM_DEMO_PASSWORD пуст, шаблонный или короче {MIN_PASSWORD} символов")
        warnings.append("Включён демо-режим (VM_DEMO=1): только для стенда, не для работы с заказчиком")

    if s.auth_mode not in ("local", "platform"):
        errors.append("VM_AUTH_MODE должен быть local или platform")
    elif s.auth_mode == "platform":
        errors.append("VM_AUTH_MODE=platform появится на этапе 3 — пока используйте local")

    if s.database_url.startswith("sqlite"):
        warnings.append("VM_DATABASE_URL указывает на SQLite — для работы нужен PostgreSQL")
    return errors, warnings


def main() -> int:
    errors, warnings = check(get_settings())
    for w in warnings:
        print(f"[preflight] ВНИМАНИЕ: {w}", file=sys.stderr)
    for e in errors:
        print(f"[preflight] ОШИБКА: {e}", file=sys.stderr)
    if errors:
        print("[preflight] Старт остановлен. Исправьте .env и перезапустите: docker compose up -d", file=sys.stderr)
        return 1
    print("[preflight] настройки в порядке")
    return 0


if __name__ == "__main__":
    sys.exit(main())
