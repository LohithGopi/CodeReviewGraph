"""Pytest configuration isolating test runs from the local SQLite database."""
import os
import tempfile
from pathlib import Path

_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="crg_pytest_")
os.environ["DATABASE_PATH"] = str(Path(_TEST_DB_DIR.name) / "test_users.db")


def pytest_unconfigure(config):
    """Remove temporary test database directory after pytest finishes."""
    _TEST_DB_DIR.cleanup()
