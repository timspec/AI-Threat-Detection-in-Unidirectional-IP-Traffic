"""
storage/db.py — SQLAlchemy Database Layer for Flows, Features, Alerts, and Models.

Implements the SQLite persistent storage schema at storage/app.db.
Supports concurrent session management and async-ready helpers.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "app.db"
DEFAULT_DB_URL = f"sqlite:///{DEFAULT_DB_PATH}"

Base = declarative_base()


# ═══════════════════════════════════════════════════════════════════════════
# SQLAlchemy Models
# ═══════════════════════════════════════════════════════════════════════════

class Sensor(Base):
    """Network capture probe/sensor node registration."""
    __tablename__ = "sensors"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    interface = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    status = Column(String(32), default="ACTIVE")
    last_heartbeat = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Flow(Base):
    """Aggregated 5-tuple bidirectional network flow record."""
    __tablename__ = "flows"

    flow_id = Column(String(64), primary_key=True, index=True)
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)

    packets_fwd = Column(Integer, default=0)
    packets_bwd = Column(Integer, default=0)
    bytes_fwd = Column(Integer, default=0)
    bytes_bwd = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)

    start_time = Column(Float, nullable=False, index=True)
    end_time = Column(Float, nullable=False)
    duration = Column(Float, default=0.0)
    state = Column(String(32), default="active")


class FeatureRecord(Base):
    """Extracted numeric/statistical feature snapshots for a flow."""
    __tablename__ = "features"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(String(64), ForeignKey("flows.flow_id"), nullable=True, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    threat_class = Column(String(64), nullable=True)
    feature_json = Column(Text, nullable=False)  # Serialized dictionary of computed features


class Alert(Base):
    """Aggregated, de-duplicated security threat alert."""
    __tablename__ = "alerts"

    alert_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    flow_id = Column(String(64), nullable=False, index=True)
    threat_class = Column(String(64), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    severity_score = Column(Float, nullable=False)

    evidence_json = Column(Text, nullable=False)
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    proto = Column(Integer, nullable=False)
    model_version = Column(String(64), nullable=False)
    status = Column(String(32), default="NEW")  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE

    annotations = relationship("Annotation", back_populates="alert", cascade="all, delete-orphan")


class ModelMetadata(Base):
    """ML model versioning, artifacts, and test evaluation metrics."""
    __tablename__ = "models"

    model_id = Column(String(64), primary_key=True)
    threat_class = Column(String(64), nullable=False)
    model_version = Column(String(64), nullable=False)
    file_path = Column(String(256), nullable=False)
    trained_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)


class Annotation(Base):
    """Analyst feedback, notes, and ground-truth validation labels."""
    __tablename__ = "annotations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), nullable=False, index=True)
    analyst_user = Column(String(64), default="analyst")
    label = Column(String(32), nullable=False)  # TRUE_POSITIVE, FALSE_POSITIVE
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert", back_populates="annotations")


# ═══════════════════════════════════════════════════════════════════════════
# Database Initializer & Session Factory
# ═══════════════════════════════════════════════════════════════════════════

_engine = None
_SessionFactory = None


def init_db(db_url: str = DEFAULT_DB_URL) -> None:
    """Initialize database tables and session factory."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = create_engine(db_url, echo=False, future=True)
    Base.metadata.create_all(_engine)
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)


def close_db() -> None:
    """Dispose of engine and release all open file handles/locks."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionFactory = None


def get_session() -> Session:
    """Yield a database session instance."""
    global _SessionFactory
    if _SessionFactory is None:
        init_db()
    return _SessionFactory()


# ═══════════════════════════════════════════════════════════════════════════
# Convenience CRUD Operations
# ═══════════════════════════════════════════════════════════════════════════

def save_flow(flow_dict: dict[str, Any], session: Optional[Session] = None) -> None:
    """Insert or update a Flow record."""
    should_close = False
    if session is None:
        session = get_session()
        should_close = True

    try:
        flow_obj = Flow(
            flow_id=flow_dict["flow_id"],
            src_ip=flow_dict["src_ip"],
            dst_ip=flow_dict["dst_ip"],
            src_port=int(flow_dict.get("src_port", 0)),
            dst_port=int(flow_dict.get("dst_port", 0)),
            protocol=int(flow_dict.get("protocol", 0)),
            packets_fwd=int(flow_dict.get("packets_fwd", 0)),
            packets_bwd=int(flow_dict.get("packets_bwd", 0)),
            bytes_fwd=int(flow_dict.get("bytes_fwd", 0)),
            bytes_bwd=int(flow_dict.get("bytes_bwd", 0)),
            total_packets=int(flow_dict.get("total_packets", 0)),
            total_bytes=int(flow_dict.get("total_bytes", 0)),
            start_time=float(flow_dict.get("start_time", 0.0)),
            end_time=float(flow_dict.get("end_time", 0.0)),
            duration=float(flow_dict.get("duration", 0.0)),
            state=str(flow_dict.get("state", "active")),
        )
        session.merge(flow_obj)
        session.commit()
    finally:
        if should_close:
            session.close()


def save_alert(alert_dict: dict[str, Any], session: Optional[Session] = None) -> None:
    """Insert or update an Alert record."""
    should_close = False
    if session is None:
        session = get_session()
        should_close = True

    try:
        evidence = alert_dict.get("evidence", {})
        evidence_str = json.dumps(evidence) if isinstance(evidence, (dict, list)) else str(evidence)

        alert_obj = Alert(
            alert_id=alert_dict["alert_id"],
            timestamp=float(alert_dict.get("timestamp", 0.0)),
            flow_id=alert_dict.get("flow_id", "unknown"),
            threat_class=alert_dict.get("threat_class", "unknown"),
            confidence=float(alert_dict.get("confidence", 0.0)),
            severity=str(alert_dict.get("severity", "MEDIUM")),
            severity_score=float(alert_dict.get("severity_score", 0.0)),
            evidence_json=evidence_str,
            src_ip=alert_dict.get("src_ip", "0.0.0.0"),
            dst_ip=alert_dict.get("dst_ip", "0.0.0.0"),
            src_port=int(alert_dict.get("src_port", 0)),
            dst_port=int(alert_dict.get("dst_port", 0)),
            proto=int(alert_dict.get("proto", 0)),
            model_version=str(alert_dict.get("model_version", "v1.0")),
            status=str(alert_dict.get("status", "NEW")),
        )
        session.merge(alert_obj)
        session.commit()
    finally:
        if should_close:
            session.close()


def get_all_alerts(limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve recent alerts ordered by timestamp descending."""
    with get_session() as session:
        stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
        results = session.scalars(stmt).all()
        return [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "flow_id": a.flow_id,
                "threat_class": a.threat_class,
                "confidence": a.confidence,
                "severity": a.severity,
                "severity_score": a.severity_score,
                "evidence": json.loads(a.evidence_json) if a.evidence_json else {},
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "proto": a.proto,
                "model_version": a.model_version,
                "status": a.status,
            }
            for a in results
        ]
