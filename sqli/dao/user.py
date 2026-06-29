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

        Supported formats:
          - Legacy: plain hex MD5 (32 hex chars)
          - Preferred: pbkdf2_sha256$<iterations>$<salt_hex>$<dk_hex>
        """
        stored = self.pwd_hash or ''

        if stored.startswith('pbkdf2_sha256$'):
            try:
                _alg, iter_s, salt_hex, dk_hex = stored.split('$', 3)
                iterations = int(iter_s)
                salt = bytes.fromhex(salt_hex)
                expected = bytes.fromhex(dk_hex)
            except Exception:
                return False

            derived = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations,
                dklen=len(expected),
            )
            return hmac.compare_digest(derived, expected)  # SECURITY_PBKDF2_VERIFY

        # Legacy fallback (do not add new MD5 hashes; migrate on password change)
        legacy = hashlib.md5(password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(stored, legacy)  # SECURITY_PBKDF2_VERIFY
