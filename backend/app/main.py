"""SecureShare backend - entry point."""

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.rate_limit import limiter
from app.routers import auth, users

app = FastAPI(title="SecureShare API", version="0.1.0")

# Rate limiting: too many requests -> 429 Too Many Requests (+ Retry-After header)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health")
def health() -> dict[str, str]:
    """Used by Docker / CI to check the API is alive. Returns no sensitive info."""
    return {"status": "ok"}
