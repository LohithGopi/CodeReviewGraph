"""API smoke tests for FastAPI endpoints."""
from fastapi.testclient import TestClient
from codereviewgraph.api.app import app

client = TestClient(app)


def test_dashboard_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "CodeReviewGraph" in response.text
    assert "<!DOCTYPE html>" in response.text


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "codereviewgraph"


def test_api_audit_clean_code():
    payload = {
        "code": "def multiply(a: int, b: int) -> int:\n    return a * b",
        "language": "python",
        "thread_id": "api-test-clean"
    }
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["report"]["health_score"] == 100
    assert data["report"]["total_findings"] == 0


def test_api_audit_vulnerable_code():
    payload = {
        "code": "import subprocess\nsubprocess.run('ls', shell=True)",
        "language": "python",
        "thread_id": "api-test-vuln"
    }
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["report"]["high_count"] >= 1


def test_api_audit_empty_code():
    payload = {"code": "   "}
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 400


def test_api_get_run_checkpoint():
    thread_id = "api-checkpoint-test"
    client.post("/api/audit", json={
        "code": "print('checkpoint')",
        "thread_id": thread_id
    })

    response = client.get(f"/api/runs/{thread_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["thread_id"] == thread_id
    assert "values" in data


def test_api_auth_google():
    # Empty/missing credentials should return 400 Bad Request
    response = client.post("/api/auth/google", json={})
    assert response.status_code == 400

    from unittest.mock import patch
    from codereviewgraph.api.auth import auth_service
    with patch.object(auth_service, "verify_id_token", return_value={
        "google_id": "google-test-sub-1",
        "email": "alex.test@gmail.com",
        "name": "Alex Test",
        "picture": "/static/avatar.png",
        "email_verified": True
    }):
        valid_res = client.post("/api/auth/google", json={"credential": "mock-test-jwt"})
        assert valid_res.status_code == 200
        data = valid_res.json()
        assert data["email"] == "alex.test@gmail.com"
        assert data["name"] == "Alex Test"
        assert data["provider"] == "google"
        assert data["authenticated"] is True


def test_api_auth_me():
    # Unauthenticated request without session cookie returns 401
    client.cookies.clear()
    unauth_res = client.get("/api/auth/me")
    assert unauth_res.status_code == 401

    # Authenticated request with session cookie returns 200 UserProfile
    from codereviewgraph.storage.user_db import user_db
    from codereviewgraph.api.auth import SESSION_COOKIE_NAME
    user = user_db.create_or_update_google_user("g-sub-me-1", "me.test@gmail.com", "Me Test")
    session_id = user_db.create_session(user["id"])
    client.cookies.set(SESSION_COOKIE_NAME, session_id)

    response = client.get("/api/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is True
    assert data["provider"] == "google"
    assert data["email"] == "me.test@gmail.com"
    client.cookies.clear()


def test_api_auth_config():
    response = client.get("/api/auth/config")
    assert response.status_code == 200
    data = response.json()
    assert "google_client_id" in data


def test_google_site_verification():
    response = client.get("/google280d8fb78c0e8560.html")
    assert response.status_code == 200
    assert "google-site-verification: google280d8fb78c0e8560.html" in response.text


def test_login_page_route():
    response = client.get("/login")
    assert response.status_code == 200
    assert "Sign in to CodeReviewGraph" in response.text
    assert "Continue with Google" in response.text


def test_playground_page_route():
    response = client.get("/playground")
    assert response.status_code == 200
    assert "Live Code Playground" in response.text
    assert "Audit Code via LangGraph" in response.text


def test_homepage_has_verification_meta_tag():
    response = client.get("/")
    assert response.status_code == 200
    assert "vGChJq6PAqIH9U9jQjgympLS9HcqrjiK5-qKtXTmXbM" in response.text
    assert "N4cEXw-VrIJLTZ4v6bZ4_ODNjIvmM1Rk7HOqOWTXIaU" in response.text
    assert 'href="/privacy"' in response.text
    assert 'href="/terms"' in response.text


def test_privacy_policy_routes():
    for path in ("/privacy", "/privacy-policy", "/privacy.html"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Privacy Policy" in response.text
        assert "Google API Services User Data Policy" in response.text


def test_terms_of_service_routes():
    for path in ("/terms", "/terms-of-service", "/terms.html"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Terms of Service" in response.text
        assert 'href="/privacy"' in response.text


def test_login_and_playground_include_legal_links():
    for path in ("/login", "/playground"):
        response = client.get(path)
        assert response.status_code == 200
        assert 'href="/privacy"' in response.text
        assert 'href="/terms"' in response.text





