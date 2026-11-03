def test_demo_profile_returns_user_input_as_json(client):
    payload = "<script>alert('XSS')</script>"

    response = client.get(
        "/api/users/demo-profile",
        query_string={"name": payload},
    )

    assert response.status_code == 200
    assert response.is_json
    assert response.json["profile"]["name"] == payload
    assert "text/html" not in response.content_type
