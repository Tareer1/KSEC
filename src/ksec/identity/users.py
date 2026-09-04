"""User identity and credential handling.

Passwords are hashed with scrypt (stdlib ``hashlib``) using a per-user random
salt, stored as ``scrypt$N$r$p$salt_hex$digest_hex``.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from ksec.core.errors import IdentityError
from ksec.db.connection import Database

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

USERNAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]{1,31}$")

USER_STATUSES = ("active", "disabled", "locked")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    if not password:
        raise IdentityError("Password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
        )
        return secrets.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class User:
    id: int
    username: str
    display_name: str
    status: str
    created_at: str


class UserRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self, username: str, password: str, display_name: str = "", status: str = "active"
    ) -> User:
        username = username.strip().lower()
        if not USERNAME_RE.fullmatch(username):
            raise IdentityError(
                f"Invalid username {username!r}: use 2-32 chars of [a-z0-9_.-], starting with [a-z0-9_]"
            )
        if status not in USER_STATUSES:
            raise IdentityError(f"Invalid user status: {status}")
        created = now_utc()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (username, display_name, password_hash, status, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (username, display_name, hash_password(password), status, created, created),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise IdentityError(f"Username {username!r} already exists") from exc
        return User(id=user_id, username=username, display_name=display_name, status=status, created_at=created)

    def get(self, user_id: int) -> User | None:
        row = self.db.query_one(
            "SELECT id, username, display_name, status, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        return self._from_row(row) if row else None

    def get_by_username(self, username: str) -> User | None:
        row = self.db.query_one(
            "SELECT id, username, display_name, status, created_at FROM users WHERE username = ?",
            (username.strip().lower(),),
        )
        return self._from_row(row) if row else None

    def list(self) -> list[User]:
        rows = self.db.query_all(
            "SELECT id, username, display_name, status, created_at FROM users ORDER BY id"
        )
        return [self._from_row(row) for row in rows]

    def set_status(self, user_id: int, status: str) -> None:
        if status not in USER_STATUSES:
            raise IdentityError(f"Invalid user status: {status}")
        self.db.execute(
            "UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_utc(), user_id),
        )

    def authenticate(self, username: str, password: str) -> User:
        """Authenticate a user; raises :class:`IdentityError` on failure."""
        user = self.get_by_username(username)
        if user is None:
            raise IdentityError("Invalid username or password", )
        row = self.db.query_one("SELECT password_hash FROM users WHERE id = ?", (user.id,))
        if row is None or not verify_password(password, row["password_hash"]):
            raise IdentityError("Invalid username or password")
        if user.status != "active":
            raise IdentityError(f"User account is {user.status}")
        return user

    @staticmethod
    def _from_row(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            username=row["username"],
            display_name=row["display_name"],
            status=row["status"],
            created_at=row["created_at"],
        )