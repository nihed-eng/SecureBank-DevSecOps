from .conftest import register, auth


def test_user_can_create_and_view_own_account(client):
    token = register(client, "alice", "alice@example.test")
    response = client.post(
        "/api/accounts", json={"label": "Everyday"}, headers=auth(token)
    )
    assert response.status_code == 201
    account_id = response.json["account"]["id"]
    assert (
        client.get(f"/api/accounts/{account_id}", headers=auth(token)).status_code
        == 200
    )


def test_user_cannot_view_another_users_account(client):
    alice = register(client, "alice", "alice@example.test")
    bob = register(client, "bobby", "bob@example.test")
    account = client.post(
        "/api/accounts", json={"label": "Private"}, headers=auth(alice)
    ).json["account"]
    response = client.get(f"/api/accounts/{account['id']}", headers=auth(bob))
    assert response.status_code == 404


def test_accounts_require_authentication(client):
    assert client.get("/api/accounts").status_code == 401
