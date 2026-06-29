import base64
import hashlib
import hmac
from typing import NamedTuple, Optional

from aiopg import Connection


class User(NamedTuple):
    id: int
    first_name: str
    middle_name: Optional[str]
    last_name: str
    username: str
    pwd_hash: str
    is_admin: bool

    @classmethod
    def from_raw(cls, raw: tuple):
        return cls(*raw) if raw else None

    @staticmethod
    async def get(conn: Connection, id_: int):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE id = %s',
                (id_,),
            )
            return User.from_raw(await cur.fetchone())

    @staticmethod
    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())

    def check_password(self, password: str):
        """Verify password.

        Supports upgraded hashes of the form:
          pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
        Falls back to legacy unsalted MD5 hex for backward compatibility.
        """
        stored = self.pwd_hash or ''
        if stored.startswith('pbkdf2_sha256$'):
            try:
                _alg, iters_s, salt_b64, dk_b64 = stored.split('$', 3)
                iters = int(iters_s)
                salt = base64.b64decode(salt_b64.encode('ascii'))
                dk_expected = base64.b64decode(dk_b64.encode('ascii'))
            except Exception:
                return False
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
            return hmac.compare_digest(dk, dk_expected)

        # INTENT:SPACE-129069-upgrade-password-hash
        legacy_md5 = hashlib.md5(password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(stored, legacy_md5)
