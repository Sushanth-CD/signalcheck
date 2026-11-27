import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture(scope="session")
def session_client():
    """Session-scoped TestClient to avoid repeated app lifespans."""
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def reset_test_state(session_client):
    """Reset cookies and rate-limiter storage between every test to ensure strict order independence.
    Fails loudly if the limiter or its storage structure changes unexpectedly.
    """
    session_client.cookies.clear()
    from app.main import limiter
    limiter.reset()
    if not hasattr(limiter, "_storage") or not hasattr(limiter._storage, "storage"):
        raise RuntimeError("SlowAPI limiter is missing expected '_storage.storage' attribute for test reset.")
    limiter._storage.storage.clear()
    yield
    session_client.cookies.clear()
    limiter.reset()
    if not hasattr(limiter, "_storage") or not hasattr(limiter._storage, "storage"):
        raise RuntimeError("SlowAPI limiter is missing expected '_storage.storage' attribute for test reset.")
    limiter._storage.storage.clear()

