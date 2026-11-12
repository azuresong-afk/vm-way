"""Пароли (scrypt), токены доступа (HMAC-SHA256) и шифрование секретов (AES-GCM)."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        # Сравнение с «пустышкой», чтобы время ответа не выдавало отсутствие пользователя.
        hashlib.scrypt(b"x", salt=b"0" * 16, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        return False
    _, n, r, p, salt, digest = stored.split("$")
    calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    return hmac.compare_digest(calc.hex(), digest)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _signing_key() -> bytes:
    key = get_settings().secret_key
    if not key:
        raise RuntimeError("VM_SECRET_KEY не задан")
    return key.encode()


def issue_token(user_id: int, token_version: int, ttl_minutes: int | None = None) -> tuple[str, int]:
    ttl = (ttl_minutes or get_settings().token_ttl_minutes) * 60
    payload = {"sub": user_id, "ver": token_version, "exp": int(time.time()) + ttl, "jti": secrets.token_hex(8)}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_signing_key(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}", ttl


def read_token(token: str) -> dict | None:
    try:
        body, sig = token.split(".", 1)
        expected = _b64(hmac.new(_signing_key(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except (ValueError, TypeError):
        # TypeError: compare_digest не принимает строки с не-ASCII символами (подпись из мусора).
        return None


def _aes_key() -> bytes:
    raw = get_settings().encryption_key
    if not raw:
        raise RuntimeError("VM_ENCRYPTION_KEY не задан")
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("VM_ENCRYPTION_KEY должен быть 32 байта в base64")
    return key


def _aad(context: str) -> bytes:
    # Контекст (например, «ssh-credential:42») привязывает шифротекст к записи: секрет, переставленный
    # в другую строку БД, не расшифруется.
    return b"vm-secret" + (b":" + context.encode() if context else b"")


def encrypt_secret(plain: str, context: str = "") -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_aes_key()).encrypt(nonce, plain.encode(), _aad(context))
    return "v1:" + base64.b64encode(nonce + ct).decode()


def decrypt_secret(stored: str | None, context: str = "") -> str:
    if not stored:
        return ""
    if not stored.startswith("v1:"):
        raise ValueError("неизвестный формат секрета")
    raw = base64.b64decode(stored[3:])
    return AESGCM(_aes_key()).decrypt(raw[:12], raw[12:], _aad(context)).decode()
