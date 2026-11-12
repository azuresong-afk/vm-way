"""Пароль сервисной учётки источника («Сканера»).

Шифруется AES-GCM (`app.security.encrypt_secret`) с контекстом `scanner-source:<id>`, как секреты
SSH-учёток: шифротекст, переставленный в строку другого источника, не расшифруется.
"""

import logging

from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ScannerSource
from app.security import decrypt_secret, encrypt_secret

log = logging.getLogger("vm.sources")


def _context(source: ScannerSource) -> str:
    return f"scanner-source:{source.id}"


def read_password(source: ScannerSource) -> str:
    return decrypt_secret(source.secret_enc, _context(source))


def write_password(source: ScannerSource, password: str) -> None:
    """Шифрует пароль источника. Нужен id — вызывать после flush."""
    source.secret_enc = encrypt_secret(password, _context(source))


def rebind_legacy(db: Session) -> int:
    """Перешифровывает пароли, сохранённые до привязки к записи (без контекста). Возвращает число.

    Вызывается при старте: после обновления или восстановления старой копии. Чтение пароля в работе
    (`read_password`) шифротекст без контекста не принимает — он переводится только здесь.
    """
    done = 0
    for source in db.scalars(select(ScannerSource).where(ScannerSource.secret_enc.is_not(None))):
        if not source.secret_enc:
            continue
        try:
            read_password(source)
            continue
        except InvalidTag:
            pass
        except Exception:  # noqa: BLE001 — битая запись не должна мешать старту
            log.warning("Пароль источника %s (%s) не читается — введите его заново", source.id, source.name)
            continue
        try:
            plain = decrypt_secret(source.secret_enc)
        except Exception:  # noqa: BLE001 — другой ключ или чужой шифротекст
            log.warning(
                "Пароль источника %s (%s) не расшифровывается текущим VM_ENCRYPTION_KEY — введите его заново",
                source.id,
                source.name,
            )
            continue
        write_password(source, plain)
        done += 1
    if done:
        db.commit()
        log.info("Пароли источников привязаны к своим записям: %s", done)
    return done
