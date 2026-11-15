import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.apk_db import init_db

@pytest.fixture(scope="session", autouse=True)
def test_db_isolation(tmp_path_factory):
    """Ensure all tests in the pytest session use an isolated temporary SQLite database."""
    temp_dir = tmp_path_factory.mktemp("test_db")
    temp_db_path = str(temp_dir / "test_signalcheck.db")
    os.environ["SIGNALCHECK_DB_PATH"] = temp_db_path
    init_db(temp_db_path)
    yield temp_db_path

@pytest.fixture(scope="session")
def session_client():
    """Session-scoped TestClient to avoid repeated app lifespans."""
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def reset_test_state(session_client):
    """Reset cookies and rate-limiter storage between every test to ensure strict order independence."""
    session_client.cookies.clear()
    try:
        from app.main import limiter
        limiter.reset()
        if hasattr(limiter, "_storage") and hasattr(limiter._storage, "storage"):
            limiter._storage.storage.clear()
    except Exception:
        pass
    yield
    session_client.cookies.clear()
    try:
        from app.main import limiter
        limiter.reset()
        if hasattr(limiter, "_storage") and hasattr(limiter._storage, "storage"):
            limiter._storage.storage.clear()
    except Exception:
        pass

