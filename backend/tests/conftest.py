"""Test setup: a SEPARATE test database, so tests never touch real data.

Runs once before the tests:
  1. point the app to "<POSTGRES_DB>_test" (instead of the real DB)
  2. create that DB if needed, create the tables
  3. after all tests: drop the tables
"""

import os

from dotenv import dotenv_values

# Must happen BEFORE "import app...": the settings are read at import time.
_root_env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
_main_db = os.environ.get("POSTGRES_DB") or _root_env.get("POSTGRES_DB", "secureshare")
os.environ["POSTGRES_DB"] = f"{_main_db.removesuffix('_test')}_test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.rate_limit import limiter, reset_account_limits  # noqa: E402

PASSWORD = "GoodPassword123!"


def _create_test_database() -> None:
    # Connect to the default "postgres" DB to run CREATE DATABASE (it can't run inside a transaction)
    admin_url = settings.database_url.set(database="postgres")
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        exists = conn.scalar(text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": settings.postgres_db})
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{settings.postgres_db}"'))
    admin.dispose()


@pytest.fixture(scope="session", autouse=True)
def test_database():
    assert settings.postgres_db.endswith("_test"), "safety: tests must never run on the real DB"
    _create_test_database()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def clean_state():
    """Every test starts from zero: empty tables + rate-limit counters reset."""
    limiter.reset()
    reset_account_limits()
    yield
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


@pytest.fixture
def client() -> TestClient:
    return make_client()


HOME_IP = "41.226.12.55"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"


def make_client(ip: str = HOME_IP, user_agent: str = BROWSER) -> TestClient:
    """A fake visitor with a chosen IP and browser.

    https: our refresh cookie is "Secure" (HTTPS only), so the test client must use HTTPS too.
    """
    return TestClient(app, base_url="https://testserver", client=(ip, 50000), headers={"User-Agent": user_agent})


@pytest.fixture
def user(client) -> dict:
    """A registered user: {'email', 'password', 'id'}."""
    email = "alice@example.com"
    r = client.post("/api/register", json={"email": email, "password": PASSWORD})
    assert r.status_code == 201
    return {"email": email, "password": PASSWORD, "id": r.json()["id"]}


@pytest.fixture
def token(client, user) -> str:
    r = client.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200
    return r.json()["access_token"]
