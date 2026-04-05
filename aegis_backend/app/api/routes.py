"""
app/api/routes.py
FastAPI route handlers for all AEGIS backend endpoints.
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Cookie, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import get_settings
from app.models.orm import Node, SystemLog, AnomalyRecord, SystemSetting, QuarantineLog
from app.models.schemas import (
    NodeOut, NodeStatusOut,
    CityMapResponse, HeatmapResponse,
    SchemaConsoleResponse,
    AnomalySummary,
    LogIngestRequest, LogIngestResponse,
    BulkLogIngestRequest, BulkLogIngestResponse,
    HealthResponse, DashboardAggregationResponse,
    ThreatInjectionRequest, ThreatScoreResponse, LogEntry,
    SystemSettingSchema, SystemSettingUpdate,
)
from app.services.analytics import (
    get_city_map, get_heatmap, get_schema_console,
    get_asset_registry, get_node_status, get_anomalies,
    get_dashboard_state, get_threat_scores, get_system_logs,
)
from app.services.forensics import detect_cloned_identities, ClonedIdentityReport
from app.services.auth import get_current_user, create_access_token, authenticate_user

try:
    from app.ml.detector import score_log_entry, score_log_batch
except ImportError:
    def score_log_entry(*args, **kwargs):
        return False, 0.5
    def score_log_batch(models, logs, threshold):
        return [(False, 0.5)] * len(logs)

logger = logging.getLogger("aegis.api")
settings = get_settings()
router = APIRouter(prefix="/api")


# ─── Authentication ───────────────────────────────────────────────────────────

@router.post("/login", tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate with username+password. Returns a JWT Bearer token.
    Credentials: admin / aegis123
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user})
    return {"access_token": access_token, "token_type": "bearer"}


# ─── Health ───────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(request: Request, session: AsyncSession = Depends(get_db)):
    """System health: DB connection, Redis, ML model status."""
    db_status = "ok"
    try:
        await session.execute(select(func.now()))
    except Exception as e:
        db_status = f"error: {e}"

    redis_status = "ok"
    try:
        from app.core.cache import get_redis
        await get_redis().ping()
    except Exception as e:
        redis_status = f"error: {e}"

    ml_status = "loaded" if hasattr(request.app.state, "models") and request.app.state.models else "not loaded"

    total_nodes = (await session.execute(select(func.count(Node.node_uuid)))).scalar() or 0
    total_logs = (await session.execute(select(func.count(SystemLog.log_id)))).scalar() or 0

    return HealthResponse(
        status="operational",
        database=db_status,
        redis=redis_status,
        ml_model=ml_status,
        total_nodes=total_nodes,
        total_logs=total_logs,
    )


# ─── Asset Registry ───────────────────────────────────────────────────────────

@router.get("/nodes", response_model=list[NodeOut], tags=["Asset Registry"])
async def list_nodes(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """
    Returns all nodes with Base64-decoded serial numbers.
    This is the true asset registry — serial numbers were masked in raw data.
    """
    return await get_asset_registry(session, skip=skip, limit=limit)


@router.get("/nodes/{node_id}/status", response_model=NodeStatusOut, tags=["Asset Registry"])
async def node_status(node_id: int, session: AsyncSession = Depends(get_db)):
    """
    Full forensic status for a single node.
    Shows true HTTP-derived status vs the deceptive JSON status.
    """
    result = await get_node_status(session, node_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    return result


# ─── Forensic City Map ────────────────────────────────────────────────────────

@router.get("/city-map", response_model=CityMapResponse, tags=["City Map"])
async def city_map(session: AsyncSession = Depends(get_db)):
    """
    All nodes with their TRUE status derived from HTTP response codes.
    Colors: HEALTHY=200, PARTIAL=206, THROTTLED=429 (DDoS indicator).
    Deliberately ignores the deceptive json_status='OPERATIONAL' field.
    """
    return await get_city_map(session)


# ─── Sleeper Heatmap ─────────────────────────────────────────────────────────

@router.get("/heatmap", response_model=HeatmapResponse, tags=["Heatmap"])
async def sleeper_heatmap(
    session: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """
    Response-time heatmap for identifying nodes with hidden malware.
    Nodes with high latency + many anomaly hits are flagged as HIGH/CRITICAL risk.
    """
    return await get_heatmap(session)


# ─── Dynamic Schema Console ───────────────────────────────────────────────────

@router.get("/schema-console", response_model=SchemaConsoleResponse, tags=["Schema Console"])
async def schema_console(
    session: AsyncSession = Depends(get_db),
    schema_version_cookie: Annotated[str | None, Cookie()] = None,
):
    """
    Live schema console — shows which cookie-based version is being parsed.
    Schema rotates at log_id=5000: load_val (v1) → L_V1 (v2).
    Pass 'schema_version_cookie' cookie with a log_id to check what version was active then.
    """
    cookie_log_id = None
    if schema_version_cookie:
        try:
            cookie_log_id = int(schema_version_cookie)
        except ValueError:
            raise HTTPException(status_code=400, detail="schema_version_cookie must be an integer log_id")

    return await get_schema_console(session, cookie_log_id=cookie_log_id)


# ─── Anomaly Detection ────────────────────────────────────────────────────────

@router.get("/anomalies", response_model=AnomalySummary, tags=["Anomaly Detection"])
async def list_anomalies(
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """
    Returns all ML-detected anomaly records, sorted by anomaly score (most suspicious first).
    Anomalies are detected by IsolationForest on the telemetry stream.
    """
    return await get_anomalies(session, skip=skip, limit=limit)


# ─── Threat Scores ────────────────────────────────────────────────────────────

@router.get("/analytics/threat-scores", response_model=ThreatScoreResponse, tags=["Analytics", "Threat Engine"])
async def threat_scores(
    session: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """
    Returns real-time threat scoring data.
    Evaluates Jitter Analysis, Frequency Fingerprinting, and Status Weighting
    to compute a 0.0-1.0 threat probability for each node.
    """
    return await get_threat_scores(session)


# ─── System Logs Stream ───────────────────────────────────────────────────────

@router.get("/system-logs", response_model=list[LogEntry], tags=["Telemetry"])
async def stream_system_logs(
    limit: int = Query(50, ge=1, le=500),
    after_id: int | None = Query(None, description="Fetch records sequentially after this Log ID."),
    session: AsyncSession = Depends(get_db),
    # NOTE: Leaving unauthenticated for simulation dashboard fetching. Can be restricted if needed.
):
    """
    Returns the real-time telemetry stream of incoming node logs.
    Use `after_id` to poll for new records since the last check.
    """
    return await get_system_logs(session, limit=limit, after_id=after_id)


# ─── Ingestion Endpoint ───────────────────────────────────────────────────────

@router.post("/ingest", response_model=LogIngestResponse, status_code=201, tags=["Ingestion"])
async def ingest_log(
    payload: LogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Ingest a single new telemetry log entry.
    Runs IsolationForest inference immediately on ingestion.
    If anomalous, persists an AnomalyRecord for audit.
    """
    # Verify node exists
    node = await session.get(Node, payload.node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {payload.node_id} not found")

    # Resolve effective load based on schema rotation
    # Note: We now estimate version based on previous max + 1, 
    # but the DB will assign the true final ID via autoincrement.
    max_log_result = await session.execute(select(func.max(SystemLog.log_id)))
    estimated_next_id = (max_log_result.scalar() or 0) + 1

    effective_load = (
        payload.l_v1 if estimated_next_id >= settings.SCHEMA_ROTATION_LOG_ID
        else payload.load_val
    )

    # Insert log (leaving log_id to be generated by DB autoincrement)
    new_log = SystemLog(
        node_id=payload.node_id,
        json_status=payload.json_status,
        http_response_code=payload.http_response_code,
        response_time_ms=payload.response_time_ms,
        load_val=payload.load_val,
        l_v1=payload.l_v1,
    )
    session.add(new_log)
    await session.flush()  # get DB-assigned log_id
    
    final_log_id = new_log.log_id

    # ML inference
    anomaly_detected = False
    anomaly_score = None

    models = getattr(request.app.state, "models", None)
    if models:
        is_anomaly, score = score_log_entry(
            models=models,
            response_time_ms=payload.response_time_ms,
            http_response_code=payload.http_response_code,
            effective_load=effective_load,
        )
        anomaly_score = round(score, 6)

        if is_anomaly:
            anomaly_detected = True
            anomaly_record = AnomalyRecord(
                node_id=payload.node_id,
                log_id=final_log_id,
                anomaly_score=score,
                detector="IsolationForest",
            )
            session.add(anomaly_record)
            logger.warning(
                "ANOMALY DETECTED — node=%d log_id=%d score=%.4f http=%d rt=%dms",
                payload.node_id, final_log_id, score,
                payload.http_response_code, payload.response_time_ms,
            )

    await session.commit()

    return LogIngestResponse(
        log_id=final_log_id,
        node_id=payload.node_id,
        anomaly_detected=anomaly_detected,
        anomaly_score=anomaly_score,
        message="Anomaly flagged — node under investigation" if anomaly_detected else "Log ingested successfully",
    )


@router.post("/ingest-bulk", response_model=BulkLogIngestResponse, status_code=201, tags=["Ingestion"])
async def ingest_logs_bulk(
    payload: BulkLogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Ingest multiple telemetry logs in a single batch.
    Optimizes performance by reducing HTTP and database overhead.
    """
    anomalies_detected = 0
    models = getattr(request.app.state, "models", None)

    # Pre-fetch existing nodes to validate IDs
    node_ids = {log.node_id for log in payload.logs}
    nodes_stmt = select(Node.node_uuid).where(Node.node_uuid.in_(node_ids))
    existing_node_ids = set((await session.execute(nodes_stmt)).scalars().all())

    # 1. Profile and filter valid logs
    valid_logs = [log for log in payload.logs if log.node_id in existing_node_ids]
    if not valid_logs:
        return BulkLogIngestResponse(ingested_count=0, anomalies_detected=0, message="No valid nodes in batch.")

    # 2. Vectorized ML Inference
    ml_results = []
    if models:
        ml_results = score_log_batch(models, valid_logs, settings.ANOMALY_THRESHOLD)
    else:
        ml_results = [(False, 0.0)] * len(valid_logs)

    # 3. Batch DB Prep: Use PostgreSQL-native bulk insert for speed
    logs_data = []
    for i, log in enumerate(valid_logs):
        logs_data.append({
            "node_id": log.node_id,
            "json_status": log.json_status,
            "http_response_code": log.http_response_code,
            "response_time_ms": log.response_time_ms,
            "load_val": log.load_val,
            "l_v1": log.l_v1,
        })
    
    # Insert logs and get their IDs
    stmt = pg_insert(SystemLog).values(logs_data).returning(SystemLog.log_id)
    result = await session.execute(stmt)
    inserted_ids = result.scalars().all()

    # 4. Persistence of Anomalies (also bulk)
    anomaly_records_data = []
    for i, (is_anomaly, score) in enumerate(ml_results):
        if is_anomaly:
            anomalies_detected += 1
            anomaly_records_data.append({
                "node_id": valid_logs[i].node_id,
                "log_id": inserted_ids[i],
                "anomaly_score": score,
                "detector": "IsolationForest",
            })
    
    if anomaly_records_data:
        # Use pg_insert for anomalies too
        stmt_anom = pg_insert(AnomalyRecord).values(anomaly_records_data)
        await session.execute(stmt_anom)

    await session.commit()

    return BulkLogIngestResponse(
        ingested_count=len(valid_logs),
        anomalies_detected=anomalies_detected,
        message=f"Successfully ingested {len(valid_logs)} logs."
    )


# ─── Forensics: Cloned Identity Detection ────────────────────────────────────

@router.get("/forensics/cloned-identities", response_model=ClonedIdentityReport, tags=["Forensics"])
async def cloned_identities(session: AsyncSession = Depends(get_db)):
    """
    Shadow Controller attack: detects nodes sharing the same decoded serial number.
    These are cloned identities — a legitimate SN reused to mask malicious hardware.
    This is one of the intentional data anomalies in the dataset.
    """
    return await detect_cloned_identities(session)


@router.get("/dashboard-aggregator", response_model=None, tags=["Analytics"])
async def dashboard_aggregator(
    full: bool = Query(False),
    session: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """
    Unified dashboard state for the Cyberpunk UI.
    Aggregates metadata, schema, nodes, heatmap, and logs.
    """
    try:
        from fastapi.responses import JSONResponse
        data = await get_dashboard_state(session, full=full)
        # Manually validate to see Pydantic error
        return JSONResponse(content=data.model_dump(mode="json", exclude_none=True))
    except Exception as e:
        import traceback
        error_msg = f"AGGREGATOR SECTOR-FAIL: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        print(error_msg)
        return JSONResponse(status_code=500, content={"detail": str(e), "traceback": traceback.format_exc()})


# ─── Simulation ───────────────────────────────────────────────────────────────

@router.post("/simulator/inject-threat", status_code=201, tags=["Simulation"])
async def inject_threat(
    payload: ThreatInjectionRequest,
    session: AsyncSession = Depends(get_db),
):
    """
    Force a node into a state of critical distress.
    This injects logs into the telemetry stream with high-risk parameters
    to trigger the 'Sword' automated quarantine.
    """
    node = await session.get(Node, payload.node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {payload.node_id} not found")

    # Generate threatening log parameters
    rt = 1000  # High latency
    code = 200 # Healthy-ish but high load and latency will trigger IsolationForest
    load = 0.95 # High system load

    if payload.threat_type == "DDOS":
        code = 429
        rt = 5
        load = 0.5
    elif payload.threat_type == "LATENCY":
        rt = 2500
        load = 0.8
    elif payload.threat_type == "MALWARE":
        rt = 150
        load = 0.99 # Outlier load
    elif payload.threat_type == "DECEPTION":
        rt = 200
        code = 403
        load = 0.75

    # Ingest the malicious log
    new_log = SystemLog(
        node_id=payload.node_id,
        json_status="OPERATIONAL",
        http_response_code=code,
        response_time_ms=rt,
        load_val=load,
        l_v1=load
    )
    session.add(new_log)
    await session.flush() # Get log_id

    import math
    # Map the UI percentage (intensity 0.0 - 1.0) back into the neural IsolationForest scale (-0.5 to +0.5)
    # Target Threat = 1 / (1 + exp(12 * score))  =>  score = -ln(1/Threat - 1) / 12
    safe_intensity = max(0.01, min(0.99, payload.intensity))
    raw_score = -math.log((1.0 / safe_intensity) - 1.0) / 12.0

    # Simulation Force: Trigger the anomaly watchdog
    anomaly_record = AnomalyRecord(
        node_id=payload.node_id,
        log_id=new_log.log_id,
        anomaly_score=raw_score,
        detector="ThreatSimulator"
    )
    session.add(anomaly_record)
    
    # Retrieve Dynamic Threshold from system
    from app.models.orm import SystemSetting
    thresh_stmt = select(SystemSetting).where(SystemSetting.key == "quarantine_threshold")
    thresh_row = (await session.execute(thresh_stmt)).scalar()
    system_threshold = float(thresh_row.value) if thresh_row else 0.50
    
    # TRIGGER THE SWORD: Simulate the automated defense mechanism if intensity is critical
    if safe_intensity >= system_threshold:
        if not node.is_quarantined:
            node.is_infected = True
            node.is_quarantined = True
            node.quarantine_reason = f"SWORD SIMULATOR: intensity {safe_intensity*100:.1f}% >= threshold {system_threshold*100:.1f}%"
            session.add(QuarantineLog(node_id=node.node_uuid, reason=node.quarantine_reason))
            logger.critical("[SHIELD_ENGAGED] THE SWORD (Simulated) isolated node %d", payload.node_id)
            
    await session.commit()
    
    logger.warning("[SIMULATOR] Threat '%s' injected into node %d. Monitoring for SWORD response...", payload.threat_type, payload.node_id)
    
    return {"message": f"Threat {payload.threat_type} injected into node {payload.node_id}. Automated quarantine should trigger if score > 0.8."}


# ─── Settings ─────────────────────────────────────────────────────────────────

@router.get("/settings/{key}", response_model=SystemSettingSchema, tags=["Settings"])
async def get_system_setting(
    key: str,
    session: AsyncSession = Depends(get_db),
):
    """Fetch a tactical system setting."""
    res = await session.execute(select(SystemSetting).where(SystemSetting.key == key))
    setting = res.scalar_one_or_none()
    
    if not setting:
        # Auto-seed default quarantine threshold if missing
        if key == "quarantine_threshold":
            new_setting = SystemSetting(key=key, value="0.5", description="Global SWORD Quarantine Threshold (0.0-1.0)")
            session.add(new_setting)
            await session.commit()
            return new_setting
        raise HTTPException(status_code=404, detail=f"Setting {key} not found")
    
    return setting


@router.patch("/settings/{key}", response_model=SystemSettingSchema, tags=["Settings"])
async def update_system_setting(
    key: str,
    payload: SystemSettingUpdate,
    session: AsyncSession = Depends(get_db),
):
    """Update a tactical system setting in real-time."""
    res = await session.execute(select(SystemSetting).where(SystemSetting.key == key))
    setting = res.scalar_one_or_none()
    
    if not setting:
        # Create it if it doesn't exist
        setting = SystemSetting(key=key, value=payload.value)
        session.add(setting)
    else:
        setting.value = payload.value
        
    await session.commit()
    await session.refresh(setting)
    
    logger.info("[MISSION_CONTROL] System setting '%s' updated to: %s", key, payload.value)
    return setting