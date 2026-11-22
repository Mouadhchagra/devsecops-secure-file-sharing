"""User endpoints (protected: a valid JWT is required)."""

from fastapi import APIRouter, Depends

from app.deps import get_current_user
from app.models import User
from app.schemas import UserOut

router = APIRouter(prefix="/api", tags=["users"])


@router.get("/profile", response_model=UserOut)
def profile(user: User = Depends(get_current_user)) -> User:
    # No user id in the URL (/profile, not /profile/<id>): you can ONLY see yourself.
    # The id comes from the signed token, so there is nothing to change to reach someone else (no IDOR).
    return user
