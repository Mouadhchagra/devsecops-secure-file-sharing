"""Task 8c tests: per-account lock (stops botnets that rotate IPs)."""

from tests.conftest import make_client


def botnet_attack(user_email: str, tries: int) -> list[int]:
    """Each try comes from a DIFFERENT IP, so the per-IP limit never triggers."""
    codes = []
    for i in range(tries):
        bot = make_client(ip=f"10.{i}.0.1")  # new IP every time (and a different network)
        codes.append(bot.post("/api/login", json={"email": user_email, "password": f"guess-{i}"}).status_code)
    return codes


def test_botnet_with_many_ips_gets_locked_out(user):
    codes = botnet_attack(user["email"], 8)
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429] * 3  # 6th try: account locked, even from a brand-new IP


def test_locked_account_refuses_even_the_right_password(user):
    botnet_attack(user["email"], 5)
    r = make_client(ip="41.226.12.55").post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 429  # locked for 15 min, whatever the password: guessing is useless now
    assert r.headers["Retry-After"] == "900"


def test_unknown_email_is_locked_the_same_way(client):
    """Same behaviour for real and fake emails, so the lock reveals nothing (no enumeration)."""
    codes = botnet_attack("nobody@example.com", 7)
    assert codes == [401] * 5 + [429] * 2


def test_successful_login_resets_the_counter(client, user):
    bad = {"email": user["email"], "password": "WrongPassword999"}
    good = {"email": user["email"], "password": user["password"]}
    for _ in range(4):
        assert make_client(ip="10.9.9.9").post("/api/login", json=bad).status_code == 401
    assert client.post("/api/login", json=good).status_code == 200  # 4 mistakes, then success -> counter back to 0
    for _ in range(4):
        assert make_client(ip="10.8.8.8").post("/api/login", json=bad).status_code == 401  # not locked yet


def test_logged_in_user_stays_logged_in_during_a_lock(client, user):
    """Lockout DoS protection: an attacker locks the login, but the real user's session keeps working."""
    client.post("/api/login", json={"email": user["email"], "password": user["password"]})
    botnet_attack(user["email"], 6)  # attacker locks the account
    assert client.post("/api/refresh").status_code == 200  # the real user is not kicked out
