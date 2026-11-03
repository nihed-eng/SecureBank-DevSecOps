import pytest
from src.app import create_app

@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "SECRET_KEY": "pytest-secret", "DATABASE": str(tmp_path / "test.db"), "VULNERABLE_DEMO": False})

@pytest.fixture
def client(app):
    return app.test_client()

def register(client, username, email):
    response = client.post("/api/auth/register", json={"username": username, "email": email, "password": "correct-horse-battery"})
    assert response.status_code == 201, response.json
    return response.json["token"]

def auth(token):
    return {"Authorization": f"Bearer {token}"}
