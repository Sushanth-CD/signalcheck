import os
import pytest
from app.apk_db import init_db

@pytest.fixture(scope="session", autouse=True)
def test_db_isolation(tmp_path_factory):
    """Ensure all tests in the pytest session use an isolated temporary SQLite database."""
    temp_dir = tmp_path_factory.mktemp("test_db")
    temp_db_path = str(temp_dir / "test_signalcheck.db")
    os.environ["SIGNALCHECK_DB_PATH"] = temp_db_path
    init_db(temp_db_path)
    yield temp_db_path
