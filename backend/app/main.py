"""SecureShare backend - entry point."""

from fastapi import FastAPI

app = FastAPI(title="SecureShare API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    """Used by Docker / CI to check the API is alive. Returns no sensitive info."""
    return {"status": "ok"}
