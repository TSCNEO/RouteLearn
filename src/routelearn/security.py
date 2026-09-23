"""Local credentials and protected router secrets."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from .config import settings

hasher = PasswordHasher()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def _secure_file(name: str, producer: object) -> bytes:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    path = settings.data_dir / name
    if not path.exists():
        try:
            with path.open("xb") as stream:
                path.chmod(0o600)
                stream.write(producer())  # type: ignore[operator]
        except FileExistsError:
            pass
    if path.stat().st_mode & 0o077:
        path.chmod(0o600)
    return path.read_bytes().strip()


def cipher() -> Fernet:
    return Fernet(_secure_file("master.key", Fernet.generate_key))


def setup_code() -> str:
    return _secure_file("setup.code", lambda: secrets.token_urlsafe(18).encode()).decode()


def encrypt(value: str) -> str:
    return cipher().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return cipher().decrypt(value.encode()).decode()


def clear_setup_code() -> None:
    Path(settings.data_dir / "setup.code").unlink(missing_ok=True)
