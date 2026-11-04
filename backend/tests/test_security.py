import pytest
from cryptography.exceptions import InvalidTag

from app.security import decrypt_secret, encrypt_secret, hash_password, issue_token, read_token, verify_password


def test_password_hash():
    h = hash_password("s3cret-password")
    assert h.startswith("scrypt$")
    assert verify_password("s3cret-password", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", None)


def test_token_roundtrip_and_tamper():
    tok, _ = issue_token(5, 2)
    assert read_token(tok)["sub"] == 5
    body, sig = tok.split(".")
    assert read_token(body + "." + sig[:-2] + "AA") is None
    assert read_token("garbage") is None


def test_token_expired():
    tok, _ = issue_token(1, 0, ttl_minutes=-1)
    assert read_token(tok) is None


def test_secret_encryption():
    enc = encrypt_secret("p@ss")
    assert enc.startswith("v1:") and "p@ss" not in enc
    assert decrypt_secret(enc) == "p@ss"
    assert encrypt_secret("p@ss") != enc  # случайный nonce
    with pytest.raises(InvalidTag):
        decrypt_secret(enc[:-4] + "AAAA")
