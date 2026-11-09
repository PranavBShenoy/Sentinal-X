"""
Integration tests for user registration, authentication, and session handling.
"""
def test_register_user_success(client):
    payload = {
        "email": "newuser@example.com",
        "username": "newuser",
        "password": "SecureP@ssw0rd999!",
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_register_duplicate_email(client, test_user):
    payload = {
        "email": test_user.email,
        "username": "differentusername",
        "password": "SecureP@ssw0rd999!",
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 409
    assert "already registered" in resp.json()["detail"]


def test_register_weak_password(client):
    payload = {
        "email": "weak@example.com",
        "username": "weakuser",
        "password": "simplepassword",  # lacks uppercase, digits
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 422


def test_login_success(client, test_user):
    payload = {
        "email": test_user.email,
        "password": "ComplexP@ssw0rd123!",
    }
    resp = client.post("/api/v1/auth/login", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_invalid_password(client, test_user):
    payload = {
        "email": test_user.email,
        "password": "IncorrectPassword!",
    }
    resp = client.post("/api/v1/auth/login", json=payload)
    assert resp.status_code == 401


def test_get_current_user_profile(client, auth_headers, test_user):
    resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == test_user.email
    assert data["username"] == test_user.username
    assert "hashed_password" not in data  # security check: password hash must never leak


def test_get_me_unauthorized(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401
