import json
import pytest


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_success(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "newuser@example.com",
            "password": "ValidPass123!"
        })
        assert res.status_code == 201
        assert b"Registration successful" in res.data

def test_register_duplicate_email(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "duplicate@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/register", json={
            "email": "duplicate@example.com",
            "password": "ValidPass123!"
        })
        assert res.status_code == 409

def test_register_weak_password(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "weak@example.com",
            "password": "short"
        })
        assert res.status_code == 400

def test_register_missing_email(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "password": "ValidPass123!"
        })
        assert res.status_code == 400

def test_register_missing_password(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "test@example.com"
        })
        assert res.status_code == 400

def test_register_invalid_email(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "notanemail",
            "password": "ValidPass123!"
        })
        assert res.status_code == 400

def test_register_password_no_uppercase(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "test@example.com",
            "password": "alllowercase123!"
        })
        assert res.status_code == 400

def test_register_password_no_special_char(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "test@example.com",
            "password": "NoSpecialChar123"
        })
        assert res.status_code == 400


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_success(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "login@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/login", json={
            "email": "login@example.com",
            "password": "ValidPass123!"
        })
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "access_token" in data
        assert "refresh_token" in data

def test_login_wrong_password(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "loginwrong@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/login", json={
            "email": "loginwrong@example.com",
            "password": "WrongPass123!"
        })
        assert res.status_code == 401

def test_login_nonexistent_user(client, app):
    with app.app_context():
        res = client.post("/api/auth/login", json={
            "email": "ghost@example.com",
            "password": "ValidPass123!"
        })
        assert res.status_code == 401

def test_login_returns_jwt_token(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "jwttest@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/login", json={
            "email": "jwttest@example.com",
            "password": "ValidPass123!"
        })
        data = json.loads(res.data)
        # JWT tokens have 3 parts separated by dots
        assert len(data["access_token"].split(".")) == 3


# ── Health check ──────────────────────────────────────────────────────────────

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["status"] == "ok"


# ── Vault — protected routes ──────────────────────────────────────────────────

def test_vault_requires_auth(client, app):
    with app.app_context():
        res = client.get("/api/vault/")
        assert res.status_code == 401

def test_vault_requires_master_password(client, app, auth_headers):
    with app.app_context():
        headers = {
            "Authorization": auth_headers["Authorization"],
            "Content-Type": "application/json"
            # No X-Master-Password
        }
        res = client.get("/api/vault/", headers=headers)
        assert res.status_code == 401

def test_vault_list_empty(client, app, auth_headers):
    with app.app_context():
        res = client.get("/api/vault/", headers=auth_headers)
        assert res.status_code == 200
        data = json.loads(res.data)
        assert isinstance(data, list)

def test_vault_create_entry(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "github.com",
            "username": "testuser",
            "password": "mypassword123"
        })
        assert res.status_code == 201
        data = json.loads(res.data)
        assert data["website"] == "github.com"
        assert data["username"] == "testuser"
        assert data["password"] == "mypassword123"

def test_vault_create_entry_missing_fields(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "github.com"
            # missing username and password
        })
        assert res.status_code == 400

def test_vault_create_and_list(client, app, auth_headers):
    with app.app_context():
        client.post("/api/vault/", headers=auth_headers, json={
            "website": "listtest.com",
            "username": "user",
            "password": "pass123"
        })
        res = client.get("/api/vault/", headers=auth_headers)
        data = json.loads(res.data)
        websites = [e["website"] for e in data]
        assert "listtest.com" in websites

def test_vault_get_single_entry(client, app, auth_headers):
    with app.app_context():
        create_res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "single.com",
            "username": "user",
            "password": "pass123"
        })
        entry_id = json.loads(create_res.data)["id"]
        res = client.get(f"/api/vault/{entry_id}", headers=auth_headers)
        assert res.status_code == 200
        assert json.loads(res.data)["website"] == "single.com"

def test_vault_get_nonexistent_entry(client, app, auth_headers):
    with app.app_context():
        res = client.get("/api/vault/99999", headers=auth_headers)
        assert res.status_code == 404

def test_vault_update_entry(client, app, auth_headers):
    with app.app_context():
        create_res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "update.com",
            "username": "olduser",
            "password": "oldpass123"
        })
        entry_id = json.loads(create_res.data)["id"]
        res = client.put(f"/api/vault/{entry_id}", headers=auth_headers, json={
            "username": "newuser"
        })
        assert res.status_code == 200
        assert json.loads(res.data)["username"] == "newuser"

def test_vault_delete_entry(client, app, auth_headers):
    with app.app_context():
        create_res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "delete.com",
            "username": "user",
            "password": "pass123"
        })
        entry_id = json.loads(create_res.data)["id"]
        res = client.delete(f"/api/vault/{entry_id}", headers=auth_headers)
        assert res.status_code == 200
        # Confirm it's gone
        res = client.get(f"/api/vault/{entry_id}", headers=auth_headers)
        assert res.status_code == 404

def test_vault_search(client, app, auth_headers):
    with app.app_context():
        client.post("/api/vault/", headers=auth_headers, json={
            "website": "searchable.com",
            "username": "user",
            "password": "pass123"
        })
        res = client.get("/api/vault/search?q=searchable", headers=auth_headers)
        assert res.status_code == 200
        data = json.loads(res.data)
        assert any("searchable" in e["website"] for e in data)

def test_vault_search_no_query(client, app, auth_headers):
    with app.app_context():
        res = client.get("/api/vault/search", headers=auth_headers)
        assert res.status_code == 400

def test_password_generator(client, app, auth_headers):
    with app.app_context():
        res = client.get("/api/vault/generate-password?length=16", headers=auth_headers)
        assert res.status_code == 200
        data = json.loads(res.data)
        assert len(data["password"]) == 16

def test_password_generator_invalid_length(client, app, auth_headers):
    with app.app_context():
        res = client.get("/api/vault/generate-password?length=200", headers=auth_headers)
        assert res.status_code == 400

def test_password_generator_requires_auth(client, app):
    with app.app_context():
        res = client.get("/api/vault/generate-password?length=16")
        assert res.status_code == 401


# ── Token refresh ─────────────────────────────────────────────────────────────

def test_refresh_token(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "refresh@example.com",
            "password": "ValidPass123!"
        })
        login_res = client.post("/api/auth/login", json={
            "email": "refresh@example.com",
            "password": "ValidPass123!"
        })
        refresh_token = json.loads(login_res.data)["refresh_token"]
        res = client.post("/api/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert res.status_code == 200
        assert "access_token" in json.loads(res.data)

def test_refresh_with_invalid_token(client, app):
    with app.app_context():
        res = client.post("/api/auth/refresh", json={
            "refresh_token": "invalid.token.here"
        })
        assert res.status_code == 401

        # ── 2FA setup ─────────────────────────────────────────────────────────────────

def test_2fa_setup_requires_auth(client, app):
    with app.app_context():
        res = client.post("/api/auth/2fa/setup")
        assert res.status_code == 401

def test_2fa_setup_returns_secret_and_uri(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/auth/2fa/setup", headers=auth_headers)
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "secret" in data
        assert "uri" in data
        assert "otpauth://" in data["uri"]

def test_2fa_verify_wrong_code(client, app, auth_headers):
    with app.app_context():
        client.post("/api/auth/2fa/setup", headers=auth_headers)
        res = client.post("/api/auth/2fa/verify", headers=auth_headers, json={
            "code": "000000"
        })
        assert res.status_code == 400

def test_2fa_verify_without_setup(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/auth/2fa/verify", headers=auth_headers, json={
            "code": "123456"
        })
        assert res.status_code == 400

def test_2fa_setup_already_enabled(client, app, auth_headers):
    with app.app_context():
        import pyotp
        # Setup
        setup_res = client.post("/api/auth/2fa/setup", headers=auth_headers)
        secret = json.loads(setup_res.data)["secret"]
        # Verify with real code
        code = pyotp.TOTP(secret).now()
        client.post("/api/auth/2fa/verify", headers=auth_headers, json={"code": code})
        # Try setup again — should fail
        res = client.post("/api/auth/2fa/setup", headers=auth_headers)
        assert res.status_code == 400