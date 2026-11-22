"""Task 8 tests: refresh token (stay logged in) + logout + theft detection."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.database import engine
from app.security import ip_network_of
from tests.conftest import make_client


def login(client, user):
    r = client.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200
    return r


def test_login_sets_a_safe_refresh_cookie(client, user):
    cookie = login(client, user).headers["set-cookie"].lower()
    assert "refresh_token=" in cookie
    assert "httponly" in cookie  # JavaScript can't read it (XSS)
    assert "secure" in cookie  # HTTPS only
    assert "samesite=strict" in cookie  # not sent by other websites (CSRF)
    assert "path=/api" in cookie


def test_only_the_hash_of_the_refresh_token_is_stored(client, user):
    login(client, user)
    raw = client.cookies.get("refresh_token")
    with engine.connect() as conn:
        stored = conn.scalar(text("SELECT token_hash FROM refresh_tokens"))
    assert stored != raw and len(stored) == 64  # SHA-256 hex, not the token


def test_refresh_gives_new_access_token_without_password(client, user):
    login(client, user)
    r = client.post("/api/refresh")
    assert r.status_code == 200
    new_access = r.json()["access_token"]
    assert client.get("/api/profile", headers={"Authorization": f"Bearer {new_access}"}).status_code == 200


def test_refresh_without_cookie_is_rejected(client):
    assert client.post("/api/refresh").status_code == 401


def test_refresh_token_is_rotated(client, user):
    login(client, user)
    first = client.cookies.get("refresh_token")
    client.post("/api/refresh")
    second = client.cookies.get("refresh_token")
    assert first != second  # every refresh = brand new refresh token


def test_reused_refresh_token_logs_out_everyone(client, user):
    """Theft detection: an old (already used) token comes back -> kill ALL sessions."""
    login(client, user)
    stolen = client.cookies.get("refresh_token")
    assert client.post("/api/refresh").status_code == 200  # real user refreshes -> "stolen" is now used
    current = client.cookies.get("refresh_token")

    client.cookies.set("refresh_token", stolen, domain="testserver.local", path="/api")
    assert client.post("/api/refresh").status_code == 401  # thief replays the old token

    client.cookies.clear()
    client.cookies.set("refresh_token", current, domain="testserver.local", path="/api")
    assert client.post("/api/refresh").status_code == 401  # even the real user's latest token is dead now


def test_expired_refresh_token_is_rejected(client, user):
    login(client, user)
    with engine.begin() as conn:
        conn.execute(text("UPDATE refresh_tokens SET expires_at = :t"), {"t": datetime.now(UTC) - timedelta(seconds=1)})
    assert client.post("/api/refresh").status_code == 401


def test_logout_kills_the_refresh_token(client, user):
    login(client, user)
    token = client.cookies.get("refresh_token")
    assert client.post("/api/logout").status_code == 204

    client.cookies.set("refresh_token", token, domain="testserver.local", path="/api")  # attacker kept a copy
    assert client.post("/api/refresh").status_code == 401  # dead in the DB, not just deleted in the browser


# ---------- Task 8b: soft binding (same network + same browser) ----------

def steal_cookie_into(thief, victim) -> None:
    """Copy the victim's refresh cookie into the thief's client (like an infostealer would)."""
    thief.cookies.set("refresh_token", victim.cookies.get("refresh_token"), domain="testserver.local", path="/api")


def test_network_is_the_first_3_parts_of_the_ip():
    assert ip_network_of("41.226.12.55") == "41.226.12.0/24"
    assert ip_network_of("41.226.12.91") == "41.226.12.0/24"  # same network
    assert ip_network_of("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
    assert ip_network_of("not-an-ip") is None


def test_refresh_works_when_only_the_last_part_of_the_ip_changes(client, user):
    login(client, user)
    router_restarted = make_client(ip="41.226.12.91")  # same home, new IP from the provider
    steal_cookie_into(router_restarted, client)
    assert router_restarted.post("/api/refresh").status_code == 200


def test_stolen_cookie_from_another_network_is_rejected(client, user):
    login(client, user)
    thief = make_client(ip="196.203.7.4")  # other city / country
    steal_cookie_into(thief, client)
    assert thief.post("/api/refresh").status_code == 401


def test_stolen_cookie_in_another_browser_is_rejected(client, user):
    login(client, user)
    thief = make_client(user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0")  # same Wi-Fi, other browser
    steal_cookie_into(thief, client)
    assert thief.post("/api/refresh").status_code == 401


def test_after_a_rejected_network_the_token_is_dead_and_new_login_works(client, user):
    login(client, user)
    cafe = make_client(ip="102.15.8.20")
    steal_cookie_into(cafe, client)
    assert cafe.post("/api/refresh").status_code == 401  # moved to a café: refresh refused
    assert client.post("/api/refresh").status_code == 401  # token was killed, even back home

    login(cafe, user)  # log in again from the café -> new network saved
    assert cafe.post("/api/refresh").status_code == 200
