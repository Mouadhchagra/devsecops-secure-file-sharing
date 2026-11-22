"""Auth endpoints: register, login, refresh, logout."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import RefreshToken, User
from app.rate_limit import (
    LOGIN_LIMIT,
    REFRESH_LIMIT,
    REGISTER_LIMIT,
    account_is_locked,
    clear_failed_logins,
    limiter,
    record_failed_login,
)
from app.schemas import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security import (
    create_access_token,
    hash_password,
    hash_refresh_token,
    ip_network_of,
    new_refresh_token,
    verify_password,
)

router = APIRouter(prefix="/api", tags=["auth"])

REFRESH_COOKIE = "refresh_token"

# ONE message for every login failure: wrong password, unknown email, disabled account.
# The attacker can never tell which one it was (no user enumeration).
INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="invalid credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
TOO_MANY_ATTEMPTS = HTTPException(
    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
    detail="too many attempts, try again later",
    headers={"Retry-After": "900"},  # 15 min
)
INVALID_REFRESH = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token")


# ---------- helpers ----------

def _client_fingerprint(request: Request) -> tuple[str | None, str | None]:
    """(network, browser) of the person sending this request.

    request.client.host = the IP that connected to us. Behind a reverse proxy (later)
    this must come from X-Forwarded-For, trusted ONLY when set by our own proxy.
    """
    ip = request.client.host if request.client else None
    user_agent = (request.headers.get("user-agent") or "")[:512] or None
    return ip_network_of(ip), user_agent


def _issue_tokens(db: Session, request: Request, response: Response, user_id: uuid.UUID) -> TokenResponse:
    """Create a new refresh token (cookie) + a new 15-min access token (JSON body)."""
    raw, token_hash = new_refresh_token()
    network, user_agent = _client_fingerprint(request)
    db.add(
        RefreshToken(
            user_id=user_id,
            token_hash=token_hash,  # only the hash goes in the DB
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_expire_days),
            ip_network=network,  # saved at login: the token is tied to this network...
            user_agent=user_agent,  # ...and to this browser
        )
    )
    db.commit()
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=raw,
        max_age=settings.refresh_expire_days * 24 * 3600,
        httponly=True,  # JavaScript can't read it -> an XSS can't steal it
        secure=True,  # only sent over HTTPS -> can't be sniffed on Wi-Fi
        samesite="strict",  # never sent by other websites -> blocks CSRF
        path="/api",  # only sent to our API, not to the frontend pages
    )
    return TokenResponse(access_token=create_access_token(user_id), expires_in=settings.jwt_expire_minutes * 60)


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/api", httponly=True, secure=True, samesite="strict")


# ---------- endpoints ----------

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(REGISTER_LIMIT)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)) -> User:
    # "request" is needed by slowapi to read the client's IP address
    # body is already validated by the schema (email format, password policy, no extra fields)
    user = User(email=body.email, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()  # the UNIQUE constraint on email decides, so 2 requests at the same time can't both win
    except IntegrityError:
        db.rollback()
        # Vague on purpose: no "this email exists" text.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="registration failed")
    db.refresh(user)
    return user  # response_model=UserOut -> only id, email, created_at go out (never the hash)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT)  # checked BEFORE argon2 runs, so a flood can't burn our CPU either
def login(request: Request, response: Response, body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    # Per-account lock (all IPs together). Checked BEFORE the DB and argon2:
    # same answer whether the email exists or not, and no CPU wasted on a locked account.
    if account_is_locked(body.email):
        raise TOO_MANY_ATTEMPTS

    user = db.scalar(select(User).where(User.email == body.email))

    # verify_password ALWAYS runs argon2 (dummy hash if the user doesn't exist),
    # so "unknown email" and "wrong password" take the same time.
    password_ok = verify_password(body.password, user.password_hash if user else None)

    if not user or not password_ok or not user.is_active:
        record_failed_login(body.email)  # counted even for unknown emails (no enumeration)
        raise INVALID_CREDENTIALS

    clear_failed_logins(body.email)
    return _issue_tokens(db, request, response, user.id)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(REFRESH_LIMIT)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None),
) -> TokenResponse:
    """Swap a valid refresh token for a NEW access token + a NEW refresh token (rotation)."""
    if not refresh_token:
        raise INVALID_REFRESH

    # FOR UPDATE = lock this row: 2 requests with the same token at the same time can't BOTH succeed
    stored = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(refresh_token)).with_for_update()
    )
    now = datetime.now(UTC)

    if stored is None:
        _clear_cookie(response)
        raise INVALID_REFRESH

    if stored.revoked_at is not None:
        # REUSE DETECTED: this token was already used once. Only 2 people can have it: the real user
        # and a thief. We can't tell who is who, so we log out ALL sessions of this user.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == stored.user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        db.commit()
        _clear_cookie(response)
        raise INVALID_REFRESH

    user = db.get(User, stored.user_id)
    if stored.expires_at <= now or user is None or not user.is_active:
        _clear_cookie(response)
        raise INVALID_REFRESH

    # SOFT BINDING: is this the same network + same browser as at login?
    network, user_agent = _client_fingerprint(request)
    if stored.ip_network is None or stored.ip_network != network or stored.user_agent != user_agent:
        # Different place or browser: maybe the real user moved, maybe a thief with a stolen cookie.
        # Either way: this token dies, and the user must log in again with the password.
        stored.revoked_at = now
        db.commit()
        _clear_cookie(response)
        raise INVALID_REFRESH

    # ROTATION: the old token dies now, a new one is given. Each refresh token works only ONCE.
    stored.revoked_at = now
    return _issue_tokens(db, request, response, user.id)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response, db: Session = Depends(get_db), refresh_token: str | None = Cookie(default=None)) -> None:
    """Kill the refresh token in the DB (not just in the browser) and delete the cookie."""
    if refresh_token:
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == hash_refresh_token(refresh_token), RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
        db.commit()
    _clear_cookie(response)
    # Always 204, even without a cookie: logout never fails and reveals nothing.
