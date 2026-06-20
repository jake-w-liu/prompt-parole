from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any

from .errors import PasswordError
from .storage import now_iso


DEFAULT_MIN_PASSWORD_LENGTH = 8
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_DKLEN = 32
SALT_BYTES = 16


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = DEFAULT_MIN_PASSWORD_LENGTH


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def validate_new_password(password: str, policy: PasswordPolicy = PasswordPolicy()) -> None:
    if len(password) < policy.min_length:
        raise PasswordError(f"Password must be at least {policy.min_length} characters.")
    if not password.strip():
        raise PasswordError("Password cannot be only whitespace.")


def hash_password(password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> dict[str, Any]:
    validate_new_password(password)
    salt = os.urandom(SALT_BYTES)
    params = {
        "n": scrypt_n,
        "r": DEFAULT_SCRYPT_R,
        "p": DEFAULT_SCRYPT_P,
        "dklen": DEFAULT_DKLEN,
    }
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=params["n"],
        r=params["r"],
        p=params["p"],
        dklen=params["dklen"],
        maxmem=max(64 * 1024 * 1024, 256 * params["n"] * params["r"]),
    )
    return {
        "version": 1,
        "kdf": "scrypt",
        "params": params,
        "salt": _b64encode(salt),
        "hash": _b64encode(digest),
        "created_at": now_iso(),
    }


def verify_password(password: str, secret: dict[str, Any]) -> bool:
    if secret.get("kdf") != "scrypt":
        return False
    try:
        params = secret["params"]
        salt = _b64decode(secret["salt"])
        expected = _b64decode(secret["hash"])
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(params["n"]),
            r=int(params["r"]),
            p=int(params["p"]),
            dklen=int(params["dklen"]),
            maxmem=max(64 * 1024 * 1024, 256 * int(params["n"]) * int(params["r"])),
        )
    except (KeyError, TypeError, ValueError, OSError):
        return False
    return hmac.compare_digest(digest, expected)
