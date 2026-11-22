"""Security helpers: password hashing (argon2id) and JWT (login ticket).

All the crypto lives in ONE file, so it is easy to review and test.
"""

import hashlib
import ipaddress
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.config import settings

# ---------- Passwords (argon2id) ----------

# Default argon2-cffi params = argon2id, 64 MiB of memory per hash, 3 passes, 16-byte random salt.
# A new random salt is made for every hash: two users with the same password get different hashes.
_hasher = PasswordHasher()

# Used when the email does not exist, so login takes the same time either way (no timing leak).
_DUMMY_HASH = _hasher.hash("dummy-password-used-only-for-timing")


def hash_password(password: str) -> str:
    """Return an argon2id hash like '$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>'."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """True if the password matches. Never raises: any problem = False."""
    if password_hash is None:
        # Unknown user: still burn the same CPU time, then say no.
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# ---------- JWT (login ticket) ----------

ALGORITHM = "HS256"  # the ONLY algorithm we accept (blocks alg=none and algorithm confusion)


def create_access_token(user_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),  # who the token belongs to (the user id, never the email/password)
        "iat": now,  # issued at
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),  # expires in 15 min
        "jti": uuid.uuid4().hex,  # unique token id (lets us revoke one token later if needed)
    }
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> uuid.UUID | None:
    """Return the user id if the token is valid, else None.

    Rejects: bad signature (tampered), expired, alg=none / other algorithms, missing claims.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[ALGORITHM],  # a list with ONE value: we never trust the token's own "alg" header
            options={"require": ["sub", "exp", "iat"]},
        )
        return uuid.UUID(payload["sub"])
    except (jwt.InvalidTokenError, ValueError):
        # InvalidTokenError covers: expired, bad signature, wrong alg, malformed, missing claims
        return None


# ---------- Refresh token (stay logged in for 7 days) ----------

def new_refresh_token() -> tuple[str, str]:
    """Return (token for the cookie, its hash for the DB).

    Random, NOT a JWT: it means nothing by itself, it only works if its hash is in our DB,
    so we can revoke it any time (logout, theft).
    """
    token = secrets.token_urlsafe(32)  # 256 bits from the OS's secure random generator
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    # SHA-256 (fast) is OK here, unlike passwords: a 256-bit random token can't be guessed,
    # so there is nothing to slow down. Fast hash = fast DB lookup.
    return hashlib.sha256(token.encode()).hexdigest()


def ip_network_of(ip: str | None) -> str | None:
    """The user's NETWORK, not the exact IP: '41.226.12.55' -> '41.226.12.0/24'.

    Small IP changes from the same provider (router restart) stay OK.
    A thief on another network (other city / country / PC) gets a different value.
    IPv4 -> first 3 parts (/24). IPv6 -> first half (/64, one home or phone usually gets one /64).
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
