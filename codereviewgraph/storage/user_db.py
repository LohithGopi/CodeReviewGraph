"""Persistent User & Session Storage for CodeReviewGraph.

Implements SQLite-backed user records, cryptographically secure sessions,
and OAuth CSRF state validation with automatic index creation and cleanup.
"""
from __future__ import annotations

import os
import sqlite3
import secrets
import datetime
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Dict, Any, Generator


def get_default_db_path() -> str:
    """Determine best SQLite database path across local dev and serverless environments."""
    env_path = os.getenv("DATABASE_PATH")
    if env_path:
        return env_path
    
    # Check for serverless read-only filesystem (e.g. Vercel / AWS Lambda)
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        tmp_dir = Path("/tmp")
        if tmp_dir.is_dir():
            return str(tmp_dir / "codereviewgraph_users.db")

    return "codereviewgraph.db"


class UserDatabase:
    """SQLite-based user and session store with connection pooling and thread safety."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        self._lock = threading.Lock()
        self._is_memory = (self.db_path == ":memory:")
        self._mem_conn: Optional[sqlite3.Connection] = None

        if self._is_memory:
            self._mem_conn = sqlite3.connect(":memory:", timeout=20.0, check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            with self._mem_conn:
                self._mem_conn.execute("PRAGMA foreign_keys = ON;")

        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a configured SQLite connection within a transaction context."""
        if self._is_memory and self._mem_conn is not None:
            with self._lock:
                with self._mem_conn:
                    yield self._mem_conn
            return

        conn = sqlite3.connect(self.db_path, timeout=20.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                try:
                    conn.execute("PRAGMA journal_mode = WAL;")
                except sqlite3.OperationalError:
                    pass
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables and performance indices if they do not exist."""
        if not self._is_memory:
            parent = Path(self.db_path).resolve().parent
            parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    google_id TEXT UNIQUE,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    picture TEXT,
                    provider TEXT NOT NULL DEFAULT 'google',
                    password_hash TEXT,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT NOT NULL
                );
            """)

            # Sessions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    user_agent TEXT,
                    ip_address TEXT
                );
            """)

            # OAuth state validation table (CSRF protection)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    redirect_url TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
            """)

            # Indices
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);")

    # --------------------------------------------------------------------------
    # User Management
    # --------------------------------------------------------------------------

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by internal ID."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by email address (case-insensitive)."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_google_id(self, google_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by Google subject identifier (sub)."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE google_id = ?", (str(google_id),))
            row = cur.fetchone()
            return dict(row) if row else None

    def create_or_update_google_user(
        self,
        google_id: str,
        email: str,
        name: str,
        picture: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Register a new Google user or update an existing verified user.
        
        Enforces security checks:
        - Prevents duplicate accounts.
        - Refuses automatic linking if an existing account belongs to a different
          authentication provider (e.g. password-based) without verified linkage.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_email = email.strip().lower()
        clean_google_id = str(google_id).strip()

        with self._get_connection() as conn:
            # 1. Existing user with this Google ID
            cur = conn.execute("SELECT * FROM users WHERE google_id = ?", (clean_google_id,))
            existing = cur.fetchone()
            if existing:
                conn.execute("""
                    UPDATE users 
                    SET name = ?, picture = COALESCE(?, picture), last_login_at = ?
                    WHERE id = ?
                """, (name, picture, now_iso, existing["id"]))
                cur = conn.execute("SELECT * FROM users WHERE id = ?", (existing["id"],))
                return dict(cur.fetchone())

            # 2. Existing user with this email
            cur = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (clean_email,))
            existing_email = cur.fetchone()
            if existing_email:
                # Security rule: If existing account is not google provider or has a different google_id, disallow automatic linking
                if existing_email["provider"] != "google":
                    raise ValueError(
                        f"An account with email '{clean_email}' already exists with provider "
                        f"'{existing_email['provider']}'. Automatic account linking without password "
                        "verification is disabled for security."
                    )
                # If provider is google but google_id wasn't set, link it now
                conn.execute("""
                    UPDATE users
                    SET google_id = ?, name = ?, picture = COALESCE(?, picture), last_login_at = ?
                    WHERE id = ?
                """, (clean_google_id, name, picture, now_iso, existing_email["id"]))
                cur = conn.execute("SELECT * FROM users WHERE id = ?", (existing_email["id"],))
                return dict(cur.fetchone())

            # 3. Create brand new user
            new_id = f"usr_{secrets.token_hex(8)}"
            conn.execute("""
                INSERT INTO users (id, google_id, email, name, picture, provider, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, 'google', ?, ?)
            """, (new_id, clean_google_id, clean_email, name, picture, now_iso, now_iso))

            cur = conn.execute("SELECT * FROM users WHERE id = ?", (new_id,))
            return dict(cur.fetchone())

    # --------------------------------------------------------------------------
    # Session Management
    # --------------------------------------------------------------------------

    def create_session(
        self,
        user_id: str,
        expires_in_seconds: int = 7 * 24 * 3600,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Create a new cryptographically secure session token for a user."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=expires_in_seconds)).isoformat()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO sessions (session_id, user_id, created_at, expires_at, user_agent, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, user_id, now.isoformat(), expires_at, user_agent, ip_address))

        return session_id

    def get_session_user(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate a session token and return the associated authenticated user profile."""
        if not session_id:
            return None

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT 
                    u.id, u.google_id, u.email, u.name, u.picture, u.provider, 
                    u.created_at, u.last_login_at, s.expires_at, s.session_id
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_id = ?
            """, (session_id,))
            row = cur.fetchone()
            if not row:
                return None

            # Check expiration
            if row["expires_at"] <= now_iso:
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                return None

            user_data = dict(row)
            return user_data

    def delete_session(self, session_id: str) -> bool:
        """Invalidate a session on logout."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            return cur.rowcount > 0

    def delete_user_sessions(self, user_id: str) -> int:
        """Invalidate all active sessions for a user (e.g., password change or global logout)."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            return cur.rowcount

    # --------------------------------------------------------------------------
    # OAuth CSRF State Validation
    # --------------------------------------------------------------------------

    def create_oauth_state(self, redirect_url: Optional[str] = None, expires_in_seconds: int = 600) -> str:
        """Create a single-use cryptographically random OAuth state token for CSRF defense."""
        state = secrets.token_urlsafe(24)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=expires_in_seconds)).isoformat()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO oauth_states (state, redirect_url, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (state, redirect_url, now.isoformat(), expires_at))

        return state

    def validate_and_consume_oauth_state(self, state: str) -> Optional[str]:
        """Validate an incoming OAuth state parameter, ensuring single-use consumption."""
        if not state:
            return None

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM oauth_states WHERE state = ?", (state,))
            row = cur.fetchone()
            if not row:
                return None

            # Always consume the state so it cannot be replayed
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))

            if row["expires_at"] <= now_iso:
                return None

            return row["redirect_url"] or ""

    def cleanup_expired(self) -> None:
        """Housekeeping: purge expired sessions and stale OAuth state tokens."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso,))
            conn.execute("DELETE FROM oauth_states WHERE expires_at <= ?", (now_iso,))


# Global default instance
user_db = UserDatabase()
