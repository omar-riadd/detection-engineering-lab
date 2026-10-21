"""
Database models and engine setup using SQLAlchemy 2.0.
SQLite in WAL mode — files are the source of truth, this is the read model.
"""
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    event,
    Float,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATABASE_PATH = PROJECT_ROOT / "api" / "detection_lab.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragmas(dbapi_connection, connection_record):
    """Configure SQLite for concurrent reads + low-latency writes."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


class Base(DeclarativeBase):
    pass


class Rule(Base):
    """
    Derived read model of a Sigma rule YAML file.
    Written by the file-sync reconciler; read by the REST API.
    """
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, index=True, default="")
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    status: Mapped[str] = mapped_column(String, index=True, default="experimental")
    severity: Mapped[str] = mapped_column(String, index=True, default="medium")

    # ATT&CK metadata (stored as pipe-separated strings for SQLite simplicity)
    techniques: Mapped[Optional[str]] = mapped_column(Text, default=None)   # e.g. "T1003.001|T1003"
    tactics: Mapped[Optional[str]] = mapped_column(Text, default=None)      # e.g. "credential-access"
    category: Mapped[Optional[str]] = mapped_column(String, default=None)
    log_source_product: Mapped[Optional[str]] = mapped_column(String, default=None)
    log_source_service: Mapped[Optional[str]] = mapped_column(String, default=None)

    # Source of truth bookkeeping
    file_path: Mapped[str] = mapped_column(Text, default="")
    raw_yaml: Mapped[Optional[str]] = mapped_column(Text, default=None)
    sha256: Mapped[str] = mapped_column(String, default="")
    sync_status: Mapped[str] = mapped_column(String, default="synced")   # synced | error
    sync_error: Mapped[Optional[str]] = mapped_column(Text, default=None)
    synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)

    # Derived fields updated after test runs
    last_test_status: Mapped[Optional[str]] = mapped_column(String, default=None)  # pass | fail
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    fp_rate: Mapped[Optional[float]] = mapped_column(Float, default=None)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "techniques": self.techniques.split("|") if self.techniques else [],
            "tactics": self.tactics.split("|") if self.tactics else [],
            "category": self.category,
            "log_source_product": self.log_source_product,
            "log_source_service": self.log_source_service,
            "file_path": self.file_path,
            "sha256": self.sha256,
            "sync_status": self.sync_status,
            "sync_error": self.sync_error,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "last_test_status": self.last_test_status,
            "last_tested_at": self.last_tested_at.isoformat() if self.last_tested_at else None,
            "fp_rate": self.fp_rate,
        }


class TestRun(Base):
    """
    Historical record of a detection test run (pytest or replay).
    Unique to this project — enables MTTD trending over time.
    """
    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String, default=None, index=True)
    run_type: Mapped[str] = mapped_column(String, default="pytest")       # pytest | replay | all
    status: Mapped[str] = mapped_column(String, default="running")        # running | pass | fail | error
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, default=None)
    output: Mapped[Optional[str]] = mapped_column(Text, default=None)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "run_type": self.run_type,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "output": self.output,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


class BypassAttempt(Base):
    """
    Parsed entry from docs/bypass_log.md.
    """
    __tablename__ = "bypass_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    technique: Mapped[str] = mapped_column(String, index=True, default="")
    technique_id: Mapped[Optional[str]] = mapped_column(String, default=None)
    evasion_method: Mapped[str] = mapped_column(Text, default="")
    outcome: Mapped[str] = mapped_column(String, default="DETECTED")    # DETECTED | EVADED | PARTIAL
    rule_hardened: Mapped[Optional[str]] = mapped_column(String, default=None)
    notes: Mapped[Optional[str]] = mapped_column(Text, default=None)
    synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "evasion_method": self.evasion_method,
            "outcome": self.outcome,
            "rule_hardened": self.rule_hardened,
            "notes": self.notes,
        }


class DeploymentLog(Base):
    """
    Record of a rule deployment push to external SIEM platforms (Wazuh, Sentinel, Splunk).
    """
    __tablename__ = "deployment_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    target: Mapped[str] = mapped_column(String)  # wazuh | sentinel | splunk | all
    status: Mapped[str] = mapped_column(String)  # deployed | simulated | unconfigured | failed
    target_rule_id: Mapped[Optional[str]] = mapped_column(String, default=None)
    details: Mapped[Optional[str]] = mapped_column(Text, default=None)
    deployed_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "target": self.target,
            "status": self.status,
            "target_rule_id": self.target_rule_id,
            "details": self.details,
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
        }


def create_tables():
    """Create all tables if they don't exist. Safe to call multiple times."""
    Base.metadata.create_all(engine)


def get_session():
    """FastAPI dependency: yields a SQLAlchemy session."""
    with Session(engine) as session:
        yield session


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
