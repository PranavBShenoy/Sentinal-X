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


def test_github_oauth_authorize_sets_session_cookie(client):
    resp = client.get("/api/v1/auth/github/authorize")
    assert resp.status_code == 200
    data = resp.json()
    assert "authorization_url" in data
    assert "state" in data

    # Assert session cookie is set
    assert "sentinelx_oauth_nonce" in resp.cookies
    nonce = resp.cookies["sentinelx_oauth_nonce"]
    assert nonce in data["state"]


def test_github_oauth_callback_forged_state_rejected(client):
    resp = client.get("/api/v1/auth/github/callback?code=mock_code&state=forged_state_123:abc:def")
    assert resp.status_code == 400
    assert "invalid or expired" in resp.json()["detail"].lower()


def test_github_oauth_callback_session_cookie_mismatch_rejected(client):
    from app.services.github_service import github_service
    valid_state = github_service.generate_oauth_state()

    # Pass mismatched session cookie
    client.cookies.set("sentinelx_oauth_nonce", "different_nonce_from_another_session")
    resp = client.get(f"/api/v1/auth/github/callback?code=mock_code&state={valid_state}")
    assert resp.status_code == 400
    assert "does not match the initiating browser session" in resp.json()["detail"]


def test_github_oauth_callback_replay_rejected(client):
    from unittest.mock import AsyncMock, patch
    from app.services.github_service import github_service

    valid_state = github_service.generate_oauth_state()
    nonce = valid_state.split(":")[1]

    mock_exchange = {
        "access_token": "gho_token_123",
        "scope": "repo",
        "token_type": "bearer",
        "github_user": {"id": 999999, "login": "testoauthuser", "email": "oauthuser@example.com"},
    }

    with patch("app.services.github_service.github_service.exchange_code", new_callable=AsyncMock) as mock_exch:
        mock_exch.return_value = mock_exchange

        # 1. First callback with valid session cookie and state succeeds
        client.cookies.set("sentinelx_oauth_nonce", nonce)
        first_resp = client.get(f"/api/v1/auth/github/callback?code=valid_code&state={valid_state}")
        assert first_resp.status_code == 200
        assert "access_token" in first_resp.json()

        # 2. Immediate replay with same state (even with cookie) fails closed with 400 Replay
        client.cookies.set("sentinelx_oauth_nonce", nonce)
        replay_resp = client.get(f"/api/v1/auth/github/callback?code=valid_code&state={valid_state}")
        assert replay_resp.status_code == 400
        assert "already been consumed" in replay_resp.json()["detail"]
