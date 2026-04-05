"""
app/models/orm.py
SQLAlchemy ORM table definitions matching the three intelligence datasets.
"""
from datetime import datetime
from sqlalchemy import (
    BigInteger, Boolean, Float, Integer, String,
    DateTime, ForeignKey, Index, text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Node(Base):
    """
    node_registry — one row per physical/virtual node in Nexus City.
    Serial numbers are stored decoded (Base64 → plaintext SN-XXXX).
    """
    __tablename__ = "nodes"

    node_uuid: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_infected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    quarantine_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )

    # Relationship to logs
    logs: Mapped[list["SystemLog"]] = relationship("SystemLog", back_populates="node")

    def __repr__(self) -> str:
        return f"<Node {self.node_uuid} serial={self.serial_number} infected={self.is_infected}>"


class SystemLog(Base):
    """
    system_logs — telemetry stream.
    Crucially: json_status is always 'OPERATIONAL' (deceptive);
    http_response_code reveals true health (200/206/429).
    """
    __tablename__ = "system_logs"

    log_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("nodes.node_uuid", ondelete="CASCADE"), nullable=False
    )
    json_status: Mapped[str] = mapped_column(String(64), nullable=False)
    http_response_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    load_val: Mapped[float | None] = mapped_column(Float, nullable=True)   # schema v1
    l_v1: Mapped[float | None] = mapped_column("L_V1", Float, nullable=True)  # schema v2
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )

    node: Mapped["Node"] = relationship("Node", back_populates="logs")

    # Derived: which schema was active when this log was written
    @property
    def active_schema_version(self) -> int:
        # Periodic oscillation: 0-5k (V1), 5k-10k (V2), 10k-15k (V1), ...
        return 2 if (self.log_id // 5000) % 2 == 1 else 1

    @property
    def effective_load(self) -> float | None:
        """Return the load metric that the active schema version points to."""
        if self.active_schema_version == 2:
            return self.l_v1
        return self.load_val

    @property
    def http_status_label(self) -> str:
        """True health label derived from HTTP code, NOT json_status."""
        code = self.http_response_code
        if code == 200:
            return "HEALTHY"
        elif code == 206:
            return "PARTIAL"
        elif code == 429:
            return "THROTTLED"       # DDoS / rate-limit indicator
        elif code >= 500:
            return "CRITICAL"
        return "UNKNOWN"

    __table_args__ = (
        Index("ix_system_logs_node_log", "node_id", "log_id"),
    )

    def __repr__(self) -> str:
        return f"<Log {self.log_id} node={self.node_id} http={self.http_response_code}>"


class SchemaConfig(Base):
    """
    schema_config — tracks which schema version / column is active at which log_id boundary.
    Cookie-based version detection: the active_column rotates at time_start boundary.
    """
    __tablename__ = "schema_config"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    time_start: Mapped[int] = mapped_column(BigInteger, nullable=False)  # log_id threshold
    active_column: Mapped[str] = mapped_column(String(64), nullable=False)

    def __repr__(self) -> str:
        return f"<Schema v{self.version} column={self.active_column} from_log={self.time_start}>"


class AnomalyRecord(Base):
    """
    Stores ML-detected anomalies for audit trail.
    Written by the ML detection layer after each inference run.
    """
    __tablename__ = "anomaly_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("nodes.node_uuid"), nullable=False)
    log_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    detector: Mapped[str] = mapped_column(String(32), nullable=False, default="IsolationForest")
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )

    __table_args__ = (
        Index("ix_anomaly_node_log", "node_id", "log_id"),
    )


class QuarantineLog(Base):
    """
    quarantine_logs — forensic audit trail for node isolation events.
    Created when the 'Sword' automated quarantine triggers.
    """
    __tablename__ = "quarantine_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("nodes.node_uuid", ondelete="CASCADE"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    isolated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    restored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<QuarantineLog node={self.node_id} reason={self.reason}>"


class SystemSetting(Base):
    """
    system_settings — Dynamic configuration keys (e.g. thresholds, timeouts).
    """
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()")
    )

    def __repr__(self) -> str:
        return f"<Setting {self.key}={self.value}>"