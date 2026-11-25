"""API route handlers for CodeReviewGraph.

Implements code review execution, checkpoint inspection,
and production-ready Google OAuth 2.0 authentication endpoints.
"""
from __future__ import annotations

import re
import secrets
import uuid
import urllib.parse
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Request, Response, Depends, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from codereviewgraph.core.state import AuditReport
from codereviewgraph.graph.workflow import review_app
from codereviewgraph.storage.checkpointer import checkpoint_manager
from codereviewgraph.storage.user_db import user_db, OtpRateLimitError
from codereviewgraph.api.auth import (
    auth_service,
    extract_session_token,
    set_session_cookie,
    clear_session_cookie,
    get_optional_user,
    send_otp_email,
)

router = APIRouter()


# ------------------------------------------------------------------------------
# Request & Response Schemas
# ------------------------------------------------------------------------------

class AuditRequest(BaseModel):
    code: str = Field(max_length=200_000, description="Source code string to review")
    language: str = Field(default="python", description="Programming language")
    file_path: Optional[str] = Field(default=None, description="Optional path to target file")
    thread_id: Optional[str] = Field(default=None, description="Run/thread ID for checkpointing")


class AuditResponse(BaseModel):
    thread_id: str
    status: str
    report: Optional[AuditReport] = None
    stage: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = Field(default=None, description="Google Identity Services (GSI) ID token JWT")
    code: Optional[str] = Field(default=None, description="OAuth 2.0 authorization code")
    redirect_uri: Optional[str] = Field(default=None, description="Redirect URI used during authorization code flow")


class SendOtpRequest(BaseModel):
    email: str = Field(description="User email address")
    name: Optional[str] = Field(default="", description="User display name")


class SendOtpResponse(BaseModel):
    status: str
    message: str
    email: str


class VerifyOtpRequest(BaseModel):
    email: str = Field(description="User email address")
    code: str = Field(description="6-digit verification code")


class AuthConfigResponse(BaseModel):
    google_client_id: str = ""
    configured: bool = False


class UserProfile(BaseModel):
    id: str
    email: str
    name: str
    picture: Optional[str] = None
    provider: str = "google"
    authenticated: bool = True


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


# ------------------------------------------------------------------------------
# Health & Status Endpoints
# ------------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint for smoke tests and orchestrator gates."""
    return HealthResponse(
        status="healthy",
        service="codereviewgraph",
        version="0.1.0"
    )


# ------------------------------------------------------------------------------
# Google OAuth 2.0 Endpoints
# ------------------------------------------------------------------------------

@router.get("/api/auth/config", response_model=AuthConfigResponse)
def auth_config():
    """Return public authentication configuration."""
    client_id = auth_service.get_client_id()
    return AuthConfigResponse(
        google_client_id=client_id,
        configured=bool(client_id)
    )


@router.get("/api/auth/google/url")
def auth_google_url(req: Request, redirect_uri: Optional[str] = None):
    """Generate a Google OAuth 2.0 authorization URL with CSRF state token."""
    if not auth_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
        )
    callback_uri = redirect_uri or auth_service.callback_url or str(req.url_for("auth_google_callback"))
    state = user_db.create_oauth_state(redirect_url=callback_uri)
    url = auth_service.build_authorization_url(state=state, redirect_uri=callback_uri)
    return {"url": url, "state": state}


@router.post("/api/auth/google", response_model=UserProfile)
def auth_google(request: GoogleAuthRequest, req: Request, response: Response):
    """
    Authenticate with Google OAuth 2.0.
    
    Accepts either:
    1. 'credential': A Google Identity Services (GSI) ID token JWT.
    2. 'code': An authorization code to exchange with Google's token endpoint.
    
    Cryptographically verifies token signature, issuer, audience, expiration,
    and requires email_verified=True. Upserts the user record and creates a
    secure HTTP-only session.
    """
    verified: Dict[str, Any]

    if request.credential:
        try:
            verified = auth_service.verify_id_token(request.credential)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    elif request.code:
        try:
            verified = auth_service.exchange_code_for_token(request.code, redirect_uri=request.redirect_uri)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication parameter required: provide 'credential' (ID token) or 'code' (authorization code)."
        )

    # Upsert user record in persistent database
    try:
        user = user_db.create_or_update_google_user(
            google_id=verified["google_id"],
            email=verified["email"],
            name=verified["name"],
            picture=verified.get("picture")
        )
    except ValueError as e:
        # Account conflict (e.g. existing email with a different provider)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {str(e)}")

    # Create cryptographically secure session
    session_id = user_db.create_session(
        user_id=user["id"],
        user_agent=req.headers.get("user-agent"),
        ip_address=req.client.host if req.client else None
    )

    # Set secure HTTP-only cookie
    set_session_cookie(response, session_id, req)

    return UserProfile(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        picture=user.get("picture"),
        provider=user.get("provider", "google"),
        authenticated=True
    )


@router.get("/api/auth/google/callback", include_in_schema=False)
def auth_google_callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """Handle redirect callback from Google OAuth 2.0 authorization server."""
    if error:
        err_param = urllib.parse.quote(error_description or error)
        return RedirectResponse(url=f"/login?error=google_{error}&message={err_param}", status_code=302)

    if not code or not state:
        return RedirectResponse(url="/login?error=missing_oauth_params", status_code=302)

    redirect_url = user_db.validate_and_consume_oauth_state(state)
    if redirect_url is None:
        return RedirectResponse(url="/login?error=invalid_csrf_state", status_code=302)

    callback_used = redirect_url if redirect_url.startswith(("http://", "https://")) else None
    target = (
        redirect_url
        if (redirect_url.startswith("/") and not redirect_url.startswith("//"))
        else "/playground"
    )

    try:
        verified = auth_service.exchange_code_for_token(code, redirect_uri=callback_used)
        user = user_db.create_or_update_google_user(
            google_id=verified["google_id"],
            email=verified["email"],
            name=verified["name"],
            picture=verified.get("picture")
        )
        session_id = user_db.create_session(
            user_id=user["id"],
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host if request.client else None
        )
        redirect_res = RedirectResponse(url=target, status_code=302)
        set_session_cookie(redirect_res, session_id, request)
        return redirect_res
    except Exception as e:
        err_param = urllib.parse.quote(str(e))
        return RedirectResponse(url=f"/login?error=auth_failed&message={err_param}", status_code=302)


@router.get("/api/auth/me", response_model=UserProfile)
def auth_me(request: Request):
    """
    Return the authenticated user profile for the active session.
    Returns HTTP 401 Unauthorized if no valid session is present.
    """
    token = extract_session_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please sign in with Google."
        )

    user = user_db.get_session_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again."
        )

    return UserProfile(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        picture=user.get("picture"),
        provider=user.get("provider", "google"),
        authenticated=True
    )


@router.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    """Invalidate active session in database and clear HTTP-only session cookie."""
    token = extract_session_token(request)
    if token:
        user_db.delete_session(token)
    clear_session_cookie(response, request)
    return {"status": "logged_out", "authenticated": False}


# ------------------------------------------------------------------------------
# Email + OTP Authentication Endpoints
# ------------------------------------------------------------------------------

@router.post("/api/auth/otp/send", response_model=SendOtpResponse)
def auth_otp_send(request: SendOtpRequest):
    """Generate and dispatch a 6-digit one-time passcode to the user's email."""
    email = request.email.strip().lower()
    if not email or not re.match(r"\A[^\s@]+@[^\s@]+\.[^\s@]+\Z", email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address."
        )

    name = request.name.strip() if request.name else email.split("@")[0].title()
    code = "".join(secrets.choice("0123456789") for _ in range(6))

    try:
        user_db.store_otp(email=email, name=name, code=code, expires_in_seconds=600)
    except OtpRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers={"Retry-After": str(e.retry_after)},
        )

    if not send_otp_email(to_email=email, name=name, code=code):
        user_db.delete_otp(email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to send verification email. Please try again later.",
        )

    return SendOtpResponse(
        status="sent",
        message=f"Verification code sent to {email}",
        email=email,
    )


@router.post("/api/auth/otp/verify", response_model=UserProfile)
def auth_otp_verify(request: VerifyOtpRequest, req: Request, response: Response):
    """Verify one-time passcode and establish an authenticated session."""
    email = request.email.strip().lower()
    code = request.code.strip()

    if not email or not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and 6-digit verification code are required."
        )

    try:
        verified = user_db.verify_otp(email=email, code=code)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Verification failed: {str(e)}")

    try:
        user = user_db.create_or_update_email_user(email=verified["email"], name=verified["name"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    session_id = user_db.create_session(
        user_id=user["id"],
        user_agent=req.headers.get("user-agent"),
        ip_address=req.client.host if req.client else None
    )
    set_session_cookie(response, session_id, req)

    return UserProfile(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        picture=user.get("picture"),
        provider=user.get("provider", "email"),
        authenticated=True
    )


# ------------------------------------------------------------------------------
# Core Audit & Graph Execution Endpoints
# ------------------------------------------------------------------------------

@router.post("/api/audit", response_model=AuditResponse)
def audit_code(request: AuditRequest, current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)):
    """Execute the multi-agent code review workflow."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")

    thread_id = request.thread_id or str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    
    initial_state = {
        "raw_code": request.code,
        "language": request.language,
        "file_path": request.file_path,
        "current_stage": "STARTED",
        "actor": current_user["id"] if current_user else "anonymous"
    }

    try:
        final_state = review_app.invoke(initial_state, config=config)
        return {
            "thread_id": thread_id,
            "status": "SUCCESS",
            "report": final_state.get("final_report"),
            "stage": final_state.get("current_stage")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit workflow failed: {str(e)}")


@router.get("/api/runs/{thread_id}")
def get_run_checkpoint(thread_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)):
    """Retrieve checkpointed state for an audit run."""
    state = checkpoint_manager.get_run_state(review_app, thread_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"No run found for thread_id '{thread_id}'")
    owner = state.get("values", {}).get("actor")
    if owner and owner != "anonymous":
        if not current_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
        if current_user["id"] != owner:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied for this audit run.")
    return state
