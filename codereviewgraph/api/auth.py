"""Google OAuth 2.0 & Session Security Service.

Implements official Google Identity Services token verification,
authorization code exchange, secure HTTP-only cookie management,
and authentication middleware dependencies for CodeReviewGraph.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Optional, Dict, Any

from fastapi import Request, Response, HTTPException, status
import httpx
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from codereviewgraph.core.config import settings
from codereviewgraph.storage.user_db import user_db


SESSION_COOKIE_NAME = "crg_session"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


class GoogleAuthService:
    """Manages Google OAuth 2.0 authentication, token verification, and sessions."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        callback_url: Optional[str] = None
    ):
        self.client_id = client_id or os.getenv("GOOGLE_CLIENT_ID", settings.google_client_id)
        self.client_secret = client_secret or os.getenv("GOOGLE_CLIENT_SECRET", settings.google_client_secret)
        self.callback_url = callback_url or os.getenv("GOOGLE_CALLBACK_URL", settings.google_callback_url)
        self._request_adapter = google_requests.Request()

    def get_client_id(self) -> str:
        """Return the active Google Client ID from configuration or environment."""
        return self.client_id or os.getenv("GOOGLE_CLIENT_ID", "")

    def is_configured(self) -> bool:
        """Check whether Google OAuth is configured with a Client ID."""
        return bool(self.get_client_id())

    def verify_id_token(self, token: str) -> Dict[str, Any]:
        """
        Cryptographically verify a Google ID token using Google's official verification library.
        
        Validates:
        1. Signature against Google's public JWK certificates.
        2. Issuer is accounts.google.com or https://accounts.google.com.
        3. Audience matches configured GOOGLE_CLIENT_ID (if set).
        4. Expiration timestamp (exp).
        5. email_verified claim is True.
        
        Raises ValueError with descriptive detail on verification failure.
        """
        if not token or not token.strip():
            raise ValueError("Authentication token is required.")

        audience = self.get_client_id() or None

        try:
            payload = google_id_token.verify_oauth2_token(
                token.strip(),
                self._request_adapter,
                audience=audience
            )
        except Exception as e:
            raise ValueError(f"Google ID token verification failed: {str(e)}")

        # Verify Issuer
        issuer = payload.get("iss")
        if issuer not in GOOGLE_ISSUERS:
            raise ValueError(f"Invalid token issuer '{issuer}'. Expected Google issuer.")

        # Verify Email Verification claim
        email_verified = payload.get("email_verified")
        if email_verified not in (True, "true", "True", 1):
            raise ValueError("Google account email is not verified. Verification is required for access.")

        # Ensure essential claims exist
        sub = payload.get("sub")
        email = payload.get("email")
        if not sub or not email:
            raise ValueError("Token missing essential identity claims (sub, email).")

        return {
            "google_id": str(sub),
            "email": str(email).lower(),
            "name": payload.get("name") or email.split("@")[0],
            "picture": payload.get("picture"),
            "email_verified": True,
            "raw_payload": payload
        }

    def build_authorization_url(self, state: str, redirect_uri: Optional[str] = None) -> str:
        """Build Google OAuth 2.0 authorization URL for redirect-based login flow."""
        client_id = self.get_client_id()
        if not client_id:
            raise ValueError("GOOGLE_CLIENT_ID is not configured. Cannot generate authorization URL.")

        callback = redirect_uri or self.callback_url or "http://localhost:8000/api/auth/google/callback"
        params = {
            "client_id": client_id,
            "redirect_uri": callback,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state,
            "prompt": "select_account"
        }
        return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_token(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange an OAuth 2.0 authorization code with Google's token endpoint
        and verify the returned ID token.
        """
        client_id = self.get_client_id()
        client_secret = self.client_secret or os.getenv("GOOGLE_CLIENT_SECRET", "")

        if not client_id or not client_secret:
            raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be configured for authorization code exchange.")

        callback = redirect_uri or self.callback_url or "http://localhost:8000/api/auth/google/callback"

        payload = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback,
            "grant_type": "authorization_code"
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(GOOGLE_TOKEN_URL, data=payload)
                if res.status_code != 200:
                    err_msg = res.text
                    try:
                        err_json = res.json()
                        err_msg = err_json.get("error_description") or err_json.get("error") or err_msg
                    except Exception:
                        pass
                    raise ValueError(f"Google token exchange failed ({res.status_code}): {err_msg}")
                token_data = res.json()
        except httpx.RequestError as e:
            raise ValueError(f"Network error communicating with Google token endpoint: {str(e)}")

        id_token_str = token_data.get("id_token")
        if not id_token_str:
            raise ValueError("Google token response did not contain an id_token.")

        # Cryptographically verify the returned ID token
        return self.verify_id_token(id_token_str)


# Global singleton
auth_service = GoogleAuthService()


# ------------------------------------------------------------------------------
# Cookie & Session Helper Functions
# ------------------------------------------------------------------------------

def is_request_secure(request: Optional[Request] = None) -> bool:
    """Determine if secure (HTTPS) cookies should be enforced."""
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return True
    if settings.environment.lower() in ("production", "prod"):
        return True
    if request:
        proto = request.headers.get("x-forwarded-proto", "").lower()
        if proto == "https" or request.url.scheme == "https":
            return True
    return False


def set_session_cookie(response: Response, session_id: str, request: Optional[Request] = None) -> None:
    """Set secure HTTP-only session cookie on the response."""
    secure = is_request_secure(request)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=7 * 24 * 3600,  # 7 days
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/"
    )


def clear_session_cookie(response: Response, request: Optional[Request] = None) -> None:
    """Delete session cookie on logout."""
    secure = is_request_secure(request)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=secure,
        samesite="lax"
    )


# ------------------------------------------------------------------------------
# Authentication Dependencies for FastAPI Routes
# ------------------------------------------------------------------------------

def extract_session_token(request: Request) -> Optional[str]:
    """Extract session token from HTTP-only cookie or Authorization header."""
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return None


def get_current_user(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency requiring an authenticated session.
    
    Raises HTTP 401 Unauthorized if no valid session is found.
    """
    token = extract_session_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in with Google."
        )

    user = user_db.get_session_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again."
        )

    return user


def get_optional_user(request: Request) -> Optional[Dict[str, Any]]:
    """FastAPI dependency returning the authenticated user if present, or None."""
    token = extract_session_token(request)
    if not token:
        return None
    return user_db.get_session_user(token)
