"""Защита от перебора пароля: временная блокировка входа после нескольких неудач.

Неудачи считаются в скользящем окне (VM_LOGIN_WINDOW_MINUTES) по трём счётчикам:

- пара «учётная запись + адрес» (VM_LOGIN_MAX_FAILURES) — обычный подбор пароля;
- адрес с любыми именами (VM_LOGIN_MAX_FAILURES_IP) — один пароль по списку учёток;
- учётная запись с любых адресов (VM_LOGIN_MAX_FAILURES_ACCOUNT) — подбор с многих адресов
  или с поддельным заголовком адреса.

Пока блокировка действует, пароль не проверяется и попытки не засчитываются: она снимается сама,
когда старые неудачи выходят из окна. Счётчики лежат в БД, поэтому общие для всех процессов API
и переживают перезапуск.
"""

import time

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import SessionLocal
from app.models import LoginFailure, User


def _key(username: str) -> str:
    return username.strip().lower()[:64]


def retry_after(db: Session, username: str, ip: str) -> int:
    """Сколько секунд вход для этой учётной записи с этого адреса ещё закрыт (0 — открыт)."""
    s = get_settings()
    window = s.login_window_minutes * 60
    now = int(time.time())
    name, ip = _key(username), ip[:64]
    cond = LoginFailure.username == name
    if ip:
        cond = or_(cond, LoginFailure.ip == ip)
    rows = db.execute(
        select(LoginFailure.username, LoginFailure.ip, LoginFailure.at)
        .where(LoginFailure.at > now - window, cond)
        .order_by(LoginFailure.at.desc())
    ).all()
    rules = [
        ([r.at for r in rows if r.username == name and r.ip == ip], s.login_max_failures),
        ([r.at for r in rows if r.username == name], s.login_max_failures_account),
    ]
    if ip:
        rules.append(([r.at for r in rows if r.ip == ip], s.login_max_failures_ip))
    wait = 0
    for times, limit in rules:
        if limit > 0 and len(times) >= limit:
            # Вход откроется, когда из окна выйдет неудача, с которой набирается предел.
            wait = max(wait, times[limit - 1] + window - now)
    return max(wait, 0)


def failure(user: User | None, username: str, ip: str, action: str = "auth.login") -> None:
    """Засчитывает неудачу и пишет её в аудит — в отдельной транзакции, как и прочие отказы."""
    now = int(time.time())
    db = SessionLocal()
    try:
        db.execute(delete(LoginFailure).where(LoginFailure.at <= now - get_settings().login_window_minutes * 60))
        db.add(LoginFailure(username=_key(username), ip=ip[:64], at=now))
        audit.record(db, user, action, result="denied", ip=ip, details={"username": username[:64]})
        db.flush()
        wait = retry_after(db, username, ip)
        if wait:
            audit.record(
                db,
                user,
                "auth.lockout",
                result="denied",
                ip=ip,
                details={"username": username[:64], "retry_after_seconds": wait},
            )
        db.commit()
    finally:
        db.close()


def clear(db: Session, username: str, ip: str) -> None:
    """Успешный вход обнуляет счётчик пары; счётчики адреса и учётной записи с других адресов остаются."""
    db.execute(delete(LoginFailure).where(LoginFailure.username == _key(username), LoginFailure.ip == ip[:64]))


def too_many(wait: int) -> str:
    minutes = max(1, -(-wait // 60))
    return f"Слишком много неудачных попыток. Повторите через {minutes} мин."
