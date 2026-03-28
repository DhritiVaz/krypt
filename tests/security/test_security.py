import json
import pytest


# ── Authentication bypass ─────────────────────────────────────────────────────

def test_no_token_rejected(client, app):
    with app.app_context():
        res = client.get("/api/vault/")
        assert res.status_code == 401

def test_malformed_token_rejected(client, app):
    with app.app_context():
        res = client.get("/api/vault/", headers={
            "Authorization": "Bearer notavalidtoken"
        })
        assert res.status_code == 401

def test_empty_token_rejected(client, app):
    with app.app_context():
        res = client.get("/api/vault/", headers={
            "Authorization": "Bearer "
        })
        assert res.status_code == 401

def test_wrong_auth_scheme_rejected(client, app):
    with app.app_context():
        res = client.get("/api/vault/", headers={
            "Authorization": "Basic dXNlcjpwYXNz"
        })
        assert res.status_code == 401

def test_tampered_token_rejected(client, app):
    with app.app_context():
        # Register and login to get a real token
        client.post("/api/auth/register", json={
            "email": "tamper@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/login", json={
            "email": "tamper@example.com",
            "password": "ValidPass123!"
        })
        token = json.loads(res.data)["access_token"]

        # Tamper with the payload section (middle part)
        parts = token.split(".")
        tampered = parts[0] + ".AAAAAAAAAAAAAAAAAAAAAA." + parts[2]

        res = client.get("/api/vault/", headers={
            "Authorization": f"Bearer {tampered}",
            "X-Master-Password": "ValidPass123!"
        })
        assert res.status_code == 401

def test_refresh_token_cannot_access_vault(client, app):
    with app.app_context():
        client.post("/api/auth/register", json={
            "email": "refreshtest@example.com",
            "password": "ValidPass123!"
        })
        res = client.post("/api/auth/login", json={
            "email": "refreshtest@example.com",
            "password": "ValidPass123!"
        })
        refresh_token = json.loads(res.data)["refresh_token"]

        # Try to use refresh token to access vault — should be rejected
        res = client.get("/api/vault/", headers={
            "Authorization": f"Bearer {refresh_token}",
            "X-Master-Password": "ValidPass123!"
        })
        assert res.status_code == 401


# ── SQL injection ─────────────────────────────────────────────────────────────

def test_sql_injection_in_email(client, app):
    with app.app_context():
        res = client.post("/api/auth/login", json={
            "email": "' OR '1'='1",
            "password": "anything"
        })
        # Should return 400 (invalid email) or 401 (not found) — never 200
        assert res.status_code in [400, 401]

def test_sql_injection_in_register(client, app):
    with app.app_context():
        res = client.post("/api/auth/register", json={
            "email": "test@test.com'; DROP TABLE users; --",
            "password": "ValidPass123!"
        })
        assert res.status_code in [400, 422]

def test_sql_injection_in_search(client, app, auth_headers):
    with app.app_context():
        res = client.get(
            "/api/vault/search?q=' OR '1'='1",
            headers=auth_headers
        )
        # Should return empty list or results — never crash
        assert res.status_code == 200
        data = json.loads(res.data)
        assert isinstance(data, list)


# ── User isolation ────────────────────────────────────────────────────────────

def test_user_cannot_access_other_users_vault(client, app):
    with app.app_context():
        # Create user A
        client.post("/api/auth/register", json={
            "email": "usera@example.com",
            "password": "ValidPass123!"
        })
        res_a = client.post("/api/auth/login", json={
            "email": "usera@example.com",
            "password": "ValidPass123!"
        })
        token_a = json.loads(res_a.data)["access_token"]
        headers_a = {
            "Authorization": f"Bearer {token_a}",
            "Content-Type": "application/json",
            "X-Master-Password": "ValidPass123!"
        }

        # User A creates a vault entry
        create_res = client.post("/api/vault/", headers=headers_a, json={
            "website": "secret.com",
            "username": "usera",
            "password": "secret123"
        })
        entry_id = json.loads(create_res.data)["id"]

        # Create user B
        client.post("/api/auth/register", json={
            "email": "userb@example.com",
            "password": "ValidPass123!"
        })
        res_b = client.post("/api/auth/login", json={
            "email": "userb@example.com",
            "password": "ValidPass123!"
        })
        token_b = json.loads(res_b.data)["access_token"]
        headers_b = {
            "Authorization": f"Bearer {token_b}",
            "Content-Type": "application/json",
            "X-Master-Password": "ValidPass123!"
        }

        # User B tries to access User A's entry — should get 404
        res = client.get(f"/api/vault/{entry_id}", headers=headers_b)
        assert res.status_code == 404

def test_user_cannot_delete_other_users_entry(client, app):
    with app.app_context():
        # Create user A and an entry
        client.post("/api/auth/register", json={
            "email": "owner@example.com",
            "password": "ValidPass123!"
        })
        res_a = client.post("/api/auth/login", json={
            "email": "owner@example.com",
            "password": "ValidPass123!"
        })
        token_a = json.loads(res_a.data)["access_token"]
        headers_a = {
            "Authorization": f"Bearer {token_a}",
            "Content-Type": "application/json",
            "X-Master-Password": "ValidPass123!"
        }
        create_res = client.post("/api/vault/", headers=headers_a, json={
            "website": "mysite.com",
            "username": "owner",
            "password": "mypassword"
        })
        entry_id = json.loads(create_res.data)["id"]

        # Create user B
        client.post("/api/auth/register", json={
            "email": "attacker@example.com",
            "password": "ValidPass123!"
        })
        res_b = client.post("/api/auth/login", json={
            "email": "attacker@example.com",
            "password": "ValidPass123!"
        })
        token_b = json.loads(res_b.data)["access_token"]
        headers_b = {
            "Authorization": f"Bearer {token_b}",
            "Content-Type": "application/json",
            "X-Master-Password": "ValidPass123!"
        }

        # User B tries to delete User A's entry
        res = client.delete(f"/api/vault/{entry_id}", headers=headers_b)
        assert res.status_code == 404


# ── Input validation ──────────────────────────────────────────────────────────

def test_empty_body_on_register(client, app):
    with app.app_context():
        res = client.post("/api/auth/register",
            data="",
            content_type="application/json"
        )
        assert res.status_code == 400

def test_empty_body_on_login(client, app):
    with app.app_context():
        res = client.post("/api/auth/login",
            data="",
            content_type="application/json"
        )
        assert res.status_code == 400

def test_xss_in_website_field(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "<script>alert('xss')</script>",
            "username": "user",
            "password": "pass123"
        })
        # Should store it (we sanitize on output) or reject — never execute
        assert res.status_code in [201, 400]
        if res.status_code == 201:
            data = json.loads(res.data)
            # Confirm it's stored as-is (escaped on output by browser)
            assert "<script>" in data["website"] or "&lt;script&gt;" in data["website"]

def test_very_long_password_input(client, app, auth_headers):
    with app.app_context():
        res = client.post("/api/vault/", headers=auth_headers, json={
            "website": "test.com",
            "username": "user",
            "password": "a" * 600  # over 512 char limit
        })
        assert res.status_code == 400

def test_missing_master_password_header(client, app, auth_headers):
    with app.app_context():
        headers = {
            "Authorization": auth_headers["Authorization"],
            "Content-Type": "application/json"
        }
        res = client.post("/api/vault/", headers=headers, json={
            "website": "test.com",
            "username": "user",
            "password": "pass123"
        })
        assert res.status_code == 401


# ── Audit log integrity ───────────────────────────────────────────────────────

def test_failed_login_is_logged(client, app):
    with app.app_context():
        from app.models.audit_log import AuditLog
        from app.extensions import db

        client.post("/api/auth/register", json={
            "email": "auditme@example.com",
            "password": "ValidPass123!"
        })
        client.post("/api/auth/login", json={
            "email": "auditme@example.com",
            "password": "WrongPassword123!"
        })

        with app.app_context():
            log = AuditLog.query.filter_by(action="LOGIN_FAILED").first()
            assert log is not None

def test_successful_login_is_logged(client, app):
    with app.app_context():
        from app.models.audit_log import AuditLog

        client.post("/api/auth/register", json={
            "email": "auditlogin@example.com",
            "password": "ValidPass123!"
        })
        client.post("/api/auth/login", json={
            "email": "auditlogin@example.com",
            "password": "ValidPass123!"
        })

        log = AuditLog.query.filter_by(action="LOGIN_SUCCESS").first()
        assert log is not None