"""Reusable FastAPI dependencies.

get_current_user = the "guard" at the door of every protected route.
Add `user: User = Depends(get_current_user)` to a route and it is protected.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import decode_access_token

# auto_error=False: we send OUR OWN 401 (same message for every case), not FastAPI's default 403
_bearer = HTTPBearer(auto_error=False)

# Same answer for: no token, bad format, tampered, expired, alg=none, deleted user, disabled user.
# The attacker never learns WHY the token failed.
NOT_AUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    # 1. Is there an "Authorization: Bearer <token>" header?
    if creds is None:
        raise NOT_AUTHENTICATED

    # 2. Is the token real? (signature, HS256 only, not expired, required claims)
    user_id = decode_access_token(creds.credentials)
    if user_id is None:
        raise NOT_AUTHENTICATED

    # 3. Does the user still exist and is still allowed in?
    #    A valid token for a deleted or banned account must NOT work.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise NOT_AUTHENTICATED

    return user
