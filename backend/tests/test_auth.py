"""Day 2 security tests: each test = one attack we proved is blocked."""

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy import text

from app.config import settings
from app.database import engine
from tests.conftest import PASSWORD


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def make_token(sub: str, minutes: int = 15, key: str | None = None, alg: str = "HS256", issued_ago: int = 0) -> str:
    iat = datetime.now(UTC) - timedelta(minutes=issued_ago)
    secret = key if key is not None else settings.jwt_secret.get_secret_value()
    return jwt.encode({"sub": sub, "iat": iat, "exp": iat + timedelta(minutes=minutes)}, secret, algorithm=alg)


# ---------- Register ----------

def test_register_ok_and_only_hash_is_stored(client):
    r = client.post("/api/register", json={"email": "Bob@Example.com", "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "bob@example.com"  # lowercased
    assert "password" not in body and "password_hash" not in body  # hash never leaves the server

    with engine.connect() as conn:
        stored = conn.scalar(text("SELECT password_hash FROM users WHERE email = 'bob@example.com'"))
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored  # DB contains only the hash


def test_register_duplicate_email_is_rejected(client, user):
    r = client.post("/api/register", json={"email": user["email"], "password": PASSWORD})
    assert r.status_code == 400
    assert r.json() == {"detail": "registration failed"}  # no "email already exists"


def test_register_weak_password_is_rejected(client):
    for weak in ["short", "aaaaaaaaaaaa", "x" * 200]:  # too short, too simple, too long (DoS)
        r = client.post("/api/register", json={"email": "c@example.com", "password": weak})
        assert r.status_code == 422


def test_register_mass_assignment_is_rejected(client):
    r = client.post("/api/register", json={"email": "d@example.com", "password": PASSWORD, "is_admin": True})
    assert r.status_code == 422


# ---------- Login ----------

def test_login_ok_returns_15_min_token(client, user):
    r = client.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900


def test_login_wrong_password_and_unknown_email_look_the_same(client, user):
    wrong_pw = client.post("/api/login", json={"email": user["email"], "password": "WrongPassword999"})
    unknown = client.post("/api/login", json={"email": "nobody@example.com", "password": "WrongPassword999"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json() == {"detail": "invalid credentials"}  # no user enumeration


def test_login_brute_force_is_throttled(client, user):
    codes = [
        client.post("/api/login", json={"email": user["email"], "password": f"guess-{i}"}).status_code
        for i in range(10)
    ]
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429] * 5  # 6th try onwards: Too Many Requests


# ---------- Protected route ----------

def test_profile_with_valid_token(client, user, token):
    r = client.get("/api/profile", headers=bearer(token))
    assert r.status_code == 200
    assert r.json()["email"] == user["email"]
    assert "password_hash" not in r.json()


def test_profile_without_token_is_rejected(client):
    assert client.get("/api/profile").status_code == 401


def test_tampered_token_is_rejected(client, token):
    header, payload, signature = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    data["sub"] = str(uuid.uuid4())  # attacker tries to become another user
    fake_payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    r = client.get("/api/profile", headers=bearer(f"{header}.{fake_payload}.{signature}"))
    assert r.status_code == 401


def test_expired_token_is_rejected(client, user):
    expired = make_token(user["id"], issued_ago=20)  # issued 20 min ago, lived 15 min
    assert client.get("/api/profile", headers=bearer(expired)).status_code == 401


def test_alg_none_token_is_rejected(client, user):
    unsigned = jwt.encode({"sub": user["id"], "exp": 9999999999, "iat": 1}, None, algorithm="none")
    assert client.get("/api/profile", headers=bearer(unsigned)).status_code == 401


def test_token_signed_with_wrong_secret_is_rejected(client, user):
    forged = make_token(user["id"], key="attacker-guessed-secret-attacker-guessed")
    assert client.get("/api/profile", headers=bearer(forged)).status_code == 401


def test_token_of_deleted_user_is_rejected(client, user, token):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user["id"]})
    assert client.get("/api/profile", headers=bearer(token)).status_code == 401
