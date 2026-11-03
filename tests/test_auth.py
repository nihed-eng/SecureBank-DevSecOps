from .conftest import register, auth


def test_register_and_login(client):
    token = register(client, "alice", "alice@example.test")
    assert client.get("/api/users/me", headers=auth(token)).status_code == 200
    response = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert response.status_code == 200
    assert response.json["user"]["username"] == "alice"


def test_rejects_short_password(client):
    response = client.post(
        "/api/auth/register",
        json={"username": "alice", "email": "a@example.test", "password": "short"},
    )
    assert response.status_code == 400


def test_login_rejects_bad_password(client):
    register(client, "alice", "alice@example.test")
    response = client.post(
        "/api/auth/login", json={"username": "alice", "password": "not-the-password"}
    )
    assert response.status_code == 401


def test_health_is_public(client):
    assert client.get("/api/health").json == {"status": "ok"}
