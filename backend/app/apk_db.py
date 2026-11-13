"""SQLite result persistence and retention management for APK static analysis (apk-static-v1).

HARD PRIVACY AND INTEGRITY CONSTRAINTS:
- Stores ONLY the apk-static-v1 JSON result, SHA-256 digest, timestamp, package_name, file_size, indicator_level, and outcome.
- NEVER stores the APK file, binary slices, or raw uploaded bytes.
- Automatic retention enforcement: trims records beyond SIGNALCHECK_APK_HISTORY_MAX (default: 200).
- Pure SQLAlchemy with SQLite.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    desc,
    select,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class APKAnalysisRecord(Base):
    """Database model for persisting static APK analysis results."""

    __tablename__ = "apk_analysis_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sha256 = Column(String(64), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, default="")
    file_size = Column(Integer, nullable=False, default=0)
    indicator_level = Column(String(32), nullable=False, default="no_notable_indicators")
    outcome = Column(String(32), nullable=False, default="SUCCESS")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    result_json = Column(Text, nullable=False)


_engine = None
_SessionFactory = None


def get_db_path() -> str:
    """Determine the SQLite database file path from environment or default."""
    return os.getenv("SIGNALCHECK_DB_PATH", "signalcheck.db")


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the database schema and session factory."""
    global _engine, _SessionFactory
    path = db_path or get_db_path()
    db_dir = os.path.dirname(path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    _engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    Base.metadata.create_all(_engine)
    _SessionFactory = sessionmaker(bind=_engine)


def get_session():
    """Obtain a new database session."""
    global _SessionFactory
    if _SessionFactory is None:
        init_db()
    return _SessionFactory()


def save_apk_result(
    sha256: str,
    package_name: str,
    file_size: int,
    indicator_level: str,
    outcome: str,
    result_data: dict[str, Any],
) -> int:
    """Persist an APK static analysis JSON payload and enforce history retention cap."""
    session = get_session()
    try:
        record = APKAnalysisRecord(
            sha256=sha256,
            package_name=package_name[:255] if package_name else "",
            file_size=file_size,
            indicator_level=indicator_level,
            outcome=outcome,
            created_at=datetime.now(timezone.utc),
            result_json=json.dumps(result_data),
        )
        session.add(record)
        session.commit()
        record_id = record.id

        # Retention Enforcement: Delete oldest records beyond max cap
        max_history = int(os.getenv("SIGNALCHECK_APK_HISTORY_MAX", "200"))
        if max_history > 0:
            total_count = session.query(APKAnalysisRecord).count()
            if total_count > max_history:
                # Find IDs of records to delete (oldest beyond max_history)
                excess = total_count - max_history
                oldest_records = (
                    session.query(APKAnalysisRecord.id)
                    .order_by(APKAnalysisRecord.created_at.asc(), APKAnalysisRecord.id.asc())
                    .limit(excess)
                    .all()
                )
                ids_to_delete = [r[0] for r in oldest_records]
                if ids_to_delete:
                    session.query(APKAnalysisRecord).filter(
                        APKAnalysisRecord.id.in_(ids_to_delete)
                    ).delete(synchronize_session=False)
                    session.commit()

        return record_id
    finally:
        session.close()


def get_apk_history(limit: int = 20, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Retrieve paginated APK analysis history ordered by newest first."""
    session = get_session()
    try:
        total = session.query(APKAnalysisRecord).count()
        records = (
            session.query(APKAnalysisRecord)
            .order_by(desc(APKAnalysisRecord.created_at), desc(APKAnalysisRecord.id))
            .offset(offset)
            .limit(limit)
            .all()
        )
        items = []
        for r in records:
            items.append({
                "id": r.id,
                "sha256": r.sha256,
                "package_name": r.package_name,
                "file_size": r.file_size,
                "indicator_level": r.indicator_level,
                "outcome": r.outcome,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            })
        return items, total
    finally:
        session.close()


def get_apk_record_by_id(record_id: int) -> Optional[dict[str, Any]]:
    """Retrieve the full stored JSON result and metadata for a specific record ID."""
    session = get_session()
    try:
        record = session.query(APKAnalysisRecord).filter_by(id=record_id).first()
        if not record:
            return None
        parsed_result = json.loads(record.result_json)
        return {
            "id": record.id,
            "sha256": record.sha256,
            "package_name": record.package_name,
            "file_size": record.file_size,
            "indicator_level": record.indicator_level,
            "outcome": record.outcome,
            "created_at": record.created_at.isoformat() if record.created_at else "",
            "result": parsed_result,
        }
    finally:
        session.close()
