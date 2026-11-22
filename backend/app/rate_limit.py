"""Rate limiting (slowapi): max N requests per minute per IP address.

Stops brute force on login (Hydra, Burp Intruder): after the limit -> 429 Too Many Requests.
"""

import hashlib

from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter
from slowapi import Limiter
from slowapi.util import get_remote_address

# key_func = how we recognize "the same attacker": here, by IP address.
# Storage = memory (fine for 1 server). With several servers we would use Redis so they share counters.
limiter = Limiter(key_func=get_remote_address)

LOGIN_LIMIT = "5/minute"  # a real user rarely mistypes 5 times in a minute; a brute-force tool does it in 1 second
REGISTER_LIMIT = "5/minute"  # slows down mass account creation and checking which emails exist
REFRESH_LIMIT = "20/minute"  # normal use = 1 refresh every 15 min; more = something is wrong


# ---------- Per-ACCOUNT limit (Task 8c): stops botnets ----------
# The per-IP limit above is useless against 1,000 IPs (1,000 x 5 tries/min).
# This counter is per EMAIL, shared by ALL IPs: 5 failed logins in 15 min -> that email is locked 15 min.
#
# It counts emails that DON'T exist too: otherwise "locked" vs "not locked" would reveal which emails are real.
# The lock is TEMPORARY (15 min), never permanent: an attacker can't lock a real user out forever (lockout DoS).

ACCOUNT_FAIL_LIMIT = parse("5/15 minutes")
_account_storage = MemoryStorage()
_account_limiter = MovingWindowRateLimiter(_account_storage)


def _key(email: str) -> str:
    # store a hash, not the email itself (no personal data in memory dumps / logs)
    return hashlib.sha256(email.encode()).hexdigest()


def account_is_locked(email: str) -> bool:
    return not _account_limiter.test(ACCOUNT_FAIL_LIMIT, _key(email))


def record_failed_login(email: str) -> None:
    _account_limiter.hit(ACCOUNT_FAIL_LIMIT, _key(email))


def clear_failed_logins(email: str) -> None:
    # successful login = start from zero (a user who mistyped 3 times is not punished later)
    _account_limiter.clear(ACCOUNT_FAIL_LIMIT, _key(email))


def reset_account_limits() -> None:
    """Used by the tests only."""
    _account_storage.reset()
