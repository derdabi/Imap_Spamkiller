import base64
import hashlib

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from .config import get_settings


class SecretDecryptionError(ValueError):
    pass


def _fernet() -> Fernet:
    secret = get_settings().encryption_secret.encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise SecretDecryptionError("Saved credentials can't be read. Reset saved credentials and re-enter them.") from exc


def can_decrypt_secret(value: str | None) -> bool:
    if not value:
        return True
    try:
        decrypt_secret(value)
        return True
    except SecretDecryptionError:
        return False
