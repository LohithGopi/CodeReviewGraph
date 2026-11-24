"""Comprehensive tests for Google OAuth 2.0 authentication and session management.

Tests cover:
1. First-time Google sign-in (user registration, secure cookie, database record).
2. Returning Google sign-in (user identification, profile update, duplicate prevention).
3. Missing parameters and user cancellation handling.
4. Invalid credentials and forged token rejection.
5. Expired token rejection.
6. Unverified email rejection.
7. Logout session invalidation and cookie clearing.
8. Protected /api/auth/me access control.
9. Account linking security (refusal of auto-linking against password accounts).
10. Session expiration handling.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from codereviewgraph.api.app import app
from codereviewgraph.api.auth import SESSION_COOKIE_NAME, auth_service
from codereviewgraph.storage.user_db import user_db, UserDatabase

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_db():
    """Ensure clean isolated SQLite database state for each test."""
    with user_db._get_connection() as conn:
        conn.execute("DELETE FROM sessions;")
        conn.execute("DELETE FROM oauth_states;")
        conn.execute("DELETE FROM users;")
    yield


def test_first_time_google_signin():
    """Scenario 1: New Google user authenticates and creates account with session cookie."""
    mock_claims = {
        "google_id": "google-sub-1001",
        "email": "jane.developer@gmail.com",
        "name": "Jane Developer",
        "picture": "https://lh3.googleusercontent.com/a/jane",
        "email_verified": True
    }

    with patch.object(auth_service, "verify_id_token", return_value=mock_claims):
        response = client.post("/api/auth/google", json={"credential": "mock-valid-id-token"})
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "jane.developer@gmail.com"
        assert data["name"] == "Jane Developer"
        assert data["picture"] == "https://lh3.googleusercontent.com/a/jane"
        assert data["provider"] == "google"
        assert data["authenticated"] is True
        assert data["id"].startswith("usr_")

        # Verify secure HTTP-only cookie
        assert SESSION_COOKIE_NAME in response.cookies
        session_token = response.cookies[SESSION_COOKIE_NAME]
        assert len(session_token) > 20

        # Verify database record
        db_user = user_db.get_user_by_google_id("google-sub-1001")
        assert db_user is not None
        assert db_user["email"] == "jane.developer@gmail.com"
        assert db_user["id"] == data["id"]

        # Verify session validity in DB
        session_user = user_db.get_session_user(session_token)
        assert session_user is not None
        assert session_user["id"] == data["id"]


def test_returning_google_signin():
    """Scenario 2: Existing Google user signs in; profile updates and duplicates are prevented."""
    # Seed initial user
    initial_user = user_db.create_or_update_google_user(
        google_id="google-sub-2002",
        email="alex.dev@gmail.com",
        name="Alex Dev",
        picture="https://old-pic.jpg"
    )

    mock_claims = {
        "google_id": "google-sub-2002",
        "email": "alex.dev@gmail.com",
        "name": "Alex Dev Updated",
        "picture": "https://new-pic.jpg",
        "email_verified": True
    }

    with patch.object(auth_service, "verify_id_token", return_value=mock_claims):
        response = client.post("/api/auth/google", json={"credential": "mock-returning-token"})
        assert response.status_code == 200
        data = response.json()
        
        # Must preserve original user ID
        assert data["id"] == initial_user["id"]
        assert data["name"] == "Alex Dev Updated"
        assert data["picture"] == "https://new-pic.jpg"

        # Verify no duplicate user created
        with user_db._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) as c FROM users WHERE google_id = ?", ("google-sub-2002",))
            assert cur.fetchone()["c"] == 1


def test_missing_auth_parameters():
    """Scenario 3: Missing both credential and code returns 400 Bad Request."""
    response = client.post("/api/auth/google", json={})
    assert response.status_code == 400
    assert "credential" in response.json()["detail"].lower()


def test_invalid_google_credentials():
    """Scenario 4: Forged or invalid token rejected with 401."""
    with patch.object(auth_service, "verify_id_token", side_effect=ValueError("Google ID token verification failed: Invalid signature")):
        response = client.post("/api/auth/google", json={"credential": "forged-fake-token"})
        assert response.status_code == 401
        assert "Invalid signature" in response.json()["detail"]


def test_expired_authentication_token():
    """Scenario 5: Expired ID token rejected with 401."""
    with patch.object(auth_service, "verify_id_token", side_effect=ValueError("Google ID token verification failed: Token expired")):
        response = client.post("/api/auth/google", json={"credential": "expired-id-token"})
        assert response.status_code == 401
        assert "Token expired" in response.json()["detail"]


def test_unverified_email_rejected():
    """Scenario 6: Token with email_verified=False is rejected."""
    with patch.object(auth_service, "verify_id_token", side_effect=ValueError("Google account email is not verified. Verification is required for access.")):
        response = client.post("/api/auth/google", json={"credential": "unverified-email-token"})
        assert response.status_code == 401
        assert "email is not verified" in response.json()["detail"].lower()


def test_logout_and_subsequent_access():
    """Scenario 7: Logout invalidates session in DB and subsequent /api/auth/me returns 401."""
    # Create user and session
    user = user_db.create_or_update_google_user(
        google_id="google-sub-logout-1",
        email="logout.user@gmail.com",
        name="Logout User"
    )
    session_id = user_db.create_session(user["id"])

    # Verify session works
    client.cookies.set(SESSION_COOKIE_NAME, session_id)
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "logout.user@gmail.com"

    # Logout
    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200
    assert logout_res.json()["authenticated"] is False

    # Cookie is invalidated in client and deleted from database
    assert user_db.get_session_user(session_id) is None

    # Subsequent /api/auth/me returns 401
    unauth_res = client.get("/api/auth/me")
    assert unauth_res.status_code == 401


def test_protected_dashboard_access_without_session():
    """Scenario 8: Accessing /api/auth/me without session cookie returns 401 Unauthorized."""
    client.cookies.clear()
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"] or "Not authenticated" in response.json()["detail"]


def test_account_linking_protection():
    """Scenario 9: Prevent silent linking of password accounts when email matches Google email."""
    # Seed a password account
    now_iso = "2026-01-01T00:00:00Z"
    with user_db._get_connection() as conn:
        conn.execute("""
            INSERT INTO users (id, google_id, email, name, provider, password_hash, created_at, last_login_at)
            VALUES ('usr_pwd_1', NULL, 'security@corporate.com', 'Existing User', 'password', 'hash123', ?, ?)
        """, (now_iso, now_iso))

    mock_claims = {
        "google_id": "google-sub-conflict-99",
        "email": "security@corporate.com",
        "name": "Attacker Impersonator",
        "picture": None,
        "email_verified": True
    }

    with patch.object(auth_service, "verify_id_token", return_value=mock_claims):
        response = client.post("/api/auth/google", json={"credential": "conflict-token"})
        # Must return 409 Conflict and refuse automatic linking
        assert response.status_code == 409
        assert "Automatic account linking without password verification is disabled" in response.json()["detail"]


def test_session_expiration():
    """Scenario 10: Expired session returns 401 and is purged from storage."""
    user = user_db.create_or_update_google_user(
        google_id="google-sub-exp-1",
        email="exp.user@gmail.com",
        name="Expired User"
    )
    # Create session with -10 seconds expiration (already expired)
    session_id = user_db.create_session(user["id"], expires_in_seconds=-10)

    client.cookies.set(SESSION_COOKIE_NAME, session_id)
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert user_db.get_session_user(session_id) is None


def test_oauth_state_csrf_validation():
    """Scenario 11: Single-use OAuth state tokens protect against CSRF attacks."""
    state = user_db.create_oauth_state(redirect_url="/playground")
    assert len(state) > 10

    # First consumption succeeds
    consumed = user_db.validate_and_consume_oauth_state(state)
    assert consumed == "/playground"

    # Second consumption fails (replay attack prevented)
    replay = user_db.validate_and_consume_oauth_state(state)
    assert replay is None


def test_auth_config_endpoint():
    """Scenario 12: Public configuration endpoint returns configured status."""
    response = client.get("/api/auth/config")
    assert response.status_code == 200
    data = response.json()
    assert "google_client_id" in data
    assert "configured" in data
