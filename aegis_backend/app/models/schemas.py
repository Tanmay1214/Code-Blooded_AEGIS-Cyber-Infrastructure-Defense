"""
app/models/schemas.py
Pydantic v2 request/response models for all API endpoints.
"""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict


# ─── Node / Asset Registry ────────────────────────────────────────────────────

class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    node_uuid: int
    serial_number: str          # Base64-decoded SN-XXXX
    user_agent: str
    is_infected: bool
    is_quarantined: bool
    quarantine_reason: str | None = None


class NodeStatusOut(BaseModel):
    node_uuid: int
    serial_number: str
    is_infected: bool
    last_http_code: int
    last_response_time_ms: int
    true_status: str            # HEALTHY / PARTIAL / THROTTLED / CRITICAL
    json_status: str            # always "OPERATIONAL" — the lie
    is_quarantined: bool
    quarantine_reason: str | None = None
    active_schema_version: int
    effective_load: float | None


# ─── City Map ─────────────────────────────────────────────────────────────────

class CityMapNode(BaseModel):
    node_uuid: int
    serial_number: str
    http_status_label: str      # Color-coded truth
    http_response_code: int
    is_infected: bool


class CityMapResponse(BaseModel):
    total: int
    nodes: list[CityMapNode]
    generated_at: datetime


# ─── Heatmap (Sleeper Detection) ──────────────────────────────────────────────

class HeatmapEntry(BaseModel):
    node_uuid: int
    serial_number: str
    avg_response_time_ms: float
    max_response_time_ms: int
    p95_response_time_ms: float
    log_count: int
    anomaly_hit_count: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class HeatmapResponse(BaseModel):
    total_nodes: int
    entries: list[HeatmapEntry]
    generated_at: datetime


# ─── Schema Console ───────────────────────────────────────────────────────────

class SchemaConsoleEntry(BaseModel):
    version: int
    active_column: str
    time_start: int             # log_id boundary
    is_current: bool


class SchemaConsoleResponse(BaseModel):
    current_version: int
    current_column: str
    latest_log_id: int
    versions: list[SchemaConsoleEntry]


# ─── Anomaly Detection ────────────────────────────────────────────────────────

class AnomalyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    node_id: int
    log_id: int
    anomaly_score: float
    detector: str
    detected_at: datetime


class AnomalySummary(BaseModel):
    total_anomalies: int
    unique_nodes_flagged: int
    anomalies: list[AnomalyOut]


# ─── Ingestion ────────────────────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    node_id: int = Field(..., description="Must match an existing node_uuid")
    json_status: str = Field(default="OPERATIONAL")
    http_response_code: int = Field(..., ge=100, le=599)
    response_time_ms: int = Field(..., ge=0)
    load_val: float | None = None
    l_v1: float | None = None


class LogIngestResponse(BaseModel):
    log_id: int
    node_id: int
    anomaly_detected: bool
    anomaly_score: float | None
    message: str


class BulkLogIngestRequest(BaseModel):
    logs: list[LogIngestRequest]


class BulkLogIngestResponse(BaseModel):
    ingested_count: int
    anomalies_detected: int
    message: str


# ─── Health ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str
    ml_model: str
    total_nodes: int
    total_logs: int


# ─── Dashboard ────────────────────────────────────────────────────────────────

class DashboardMetadata(BaseModel):
    system_time: int
    latest_log_timestamp: str | None = None
    total_logs_processed: int
    active_threats: int
    total_anomalies: int
    status: str


class SchemaEngineState(BaseModel):
    current_version: int
    active_column: str
    rotation_timer: str
    sync_status: str


class DashboardNode(BaseModel):
    id: int
    pos: dict | None = None
    is_infected: bool
    is_quarantined: bool = False
    conflict_detected: bool
    last_http_code: int
    reported_json: str
    decoded_serial: str | None = None
    encoded_ua: str | None = None


class LogEntry(BaseModel):
    id: int
    timestamp: str
    node_id: int
    message: str
    status: str
    http_code: int


class DashboardAggregationResponse(BaseModel):
    metadata: DashboardMetadata
    schema_engine: SchemaEngineState
    nodes: list[DashboardNode] | None = None
    heatmap: list[dict]
    terminal_logs: list[LogEntry]


# ─── Simulation ───────────────────────────────────────────────────────────────

class ThreatInjectionRequest(BaseModel):
    node_id: int
    threat_type: Literal["DDOS", "LATENCY", "MALWARE"]
    intensity: float = Field(0.9, ge=0.0, le=1.0)


# ─── Threat Score Engine ──────────────────────────────────────────────────────

class ThreatScoreEntry(BaseModel):
    node_uuid: int
    serial_number: str
    threat_score: float  # 0.0 to 1.0
    jitter_variance: float
    logs_per_second: float
    status_multiplier: float


class ThreatScoreResponse(BaseModel):
    active_nodes: int
    scores: list[ThreatScoreEntry]
    generated_at: datetime
