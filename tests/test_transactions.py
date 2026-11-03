from .conftest import register, auth
from src.database import get_db


def test_transaction_list_is_scoped_to_user(client, app):
    alice = register(client, "alice", "alice@example.test")
    bob = register(client, "bobby", "bob@example.test")
    account = client.post(
        "/api/accounts", json={"label": "A"}, headers=auth(alice)
    ).json["account"]
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO transactions(account_id,description,amount_cents) VALUES (?,?,?)",
            (account["id"], "Test deposit", 1250),
        )
        db.commit()
    assert (
        len(client.get("/api/transactions", headers=auth(alice)).json["transactions"])
        == 1
    )
    assert (
        len(client.get("/api/transactions", headers=auth(bob)).json["transactions"])
        == 0
    )


def test_transaction_filter(client, app):
    token = register(client, "alice", "alice@example.test")
    account = client.post("/api/accounts", json={}, headers=auth(token)).json["account"]
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO transactions(account_id,description,amount_cents) VALUES (?,?,?)",
            (account["id"], "Coffee", -450),
        )
        db.commit()
    response = client.get(
        f"/api/transactions?account_id={account['id']}", headers=auth(token)
    )
    assert response.status_code == 200
    assert response.json["transactions"][0]["description"] == "Coffee"
