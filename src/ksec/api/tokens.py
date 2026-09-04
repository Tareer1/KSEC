"""API bearer-token store.

Only the SHA-256 digest of a token is persisted. The plaintext token is
returned exactly once at creation — there is no way to recover it later.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return "ksec_" + secrets.token_hex(24)


@dataclass(frozen=True)
class ApiToken:
    id: int
    name: str
    user_id: int
    created_at: str
    last_used_at: str | None
    revoked: bool

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "revoked": self.revoked,
        }


class TokenStore:
    def __init__(self, db: Database):
        self.db = db

    def create(self, *, user_id: int, name: str = "") -> tuple[str, ApiToken]:
        token = new_token()
        cursor = self.db.execute(
            "INSERT INTO api_tokens (token_hash, name, user_id, created_at) VALUES (?, ?, ?, ?)",
            (hash_token(token), name.strip(), user_id, now_utc()),
        )
        record = self.get(cursor.lastrowid)
        assert record is not None
        return token, record

    def get(self, token_id: int) -> ApiToken | None:
        row = self.db.query_one("SELECT * FROM api_tokens WHERE id = ?", (token_id,))
        return self._from_row(row) if row else None

    def list(self, user_id: int | None = None) -> list[ApiToken]:
        if user_id is not None:
            rows = self.db.query_all(
                "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY id", (user_id,)
            )
        else:
            rows = self.db.query_all("SELECT * FROM api_tokens ORDER BY id")
        return [self._from_row(row) for row in rows]

    def revoke(self, token_id: int, *, user_id: int | None = None) -> bool:
        if user_id is not None:
            cursor = self.db.execute(
                "UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?",
                (token_id, user_id),
            )
        else:
            cursor = self.db.execute(
                "UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,)
            )
        return cursor.rowcount > 0

    def validate(self, token: str) -> ApiToken | None:
        """Return the token record if valid (exists, not revoked, user active)."""
        if not token:
            return None
        digest = hash_token(token)
        row = self.db.query_one(
            "SELECT t.* FROM api_tokens t JOIN users u ON u.id = t.user_id"
            " WHERE t.token_hash = ? AND t.revoked = 0 AND u.status = 'active'",
            (digest,),
        )
        if row is None:
            return None
        self.db.execute(
            "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_utc(), row["id"])
        )
        return self._from_row(row)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ApiToken:
        return ApiToken(
            id=row["id"],
            name=row["name"],
            user_id=row["user_id"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked=bool(row["revoked"]),
        )
