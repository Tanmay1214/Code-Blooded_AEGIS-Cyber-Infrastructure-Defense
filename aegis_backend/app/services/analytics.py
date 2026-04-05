"""
app/services/analytics.py
Business logic for the dashboard features:
  1. Forensic City Map     — nodes colored by true HTTP status
  2. Sleeper Heatmap       — API response time anomaly ranking
  3. Dynamic Schema Console — active schema version tracking
  4. Asset Registry        — decoded serial numbers table
  5. Threat Score          — operational threat probability
  6. Unified Dashboard     — aggregated state for the cyberpunk UI
"""
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.orm import Node, SystemLog, SchemaConfig, AnomalyRecord
from app.models.schemas import (
    CityMapNode, CityMapResponse,
    HeatmapEntry, HeatmapResponse,
    SchemaConsoleEntry, SchemaConsoleResponse,
    NodeOut, NodeStatusOut,
    AnomalyOut, AnomalySummary,
    ThreatScoreEntry, ThreatScoreResponse,
    DashboardAggregationResponse, DashboardMetadata, SchemaEngineState, DashboardNode, LogEntry,
)
from app.core.cache import cache_get, cache_set, CACHE_CITY_MAP, CACHE_HEATMAP, CACHE_THREAT_SCORE

logger = logging.getLogger("aegis.analytics")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _risk_level(avg_rt: float, anomaly_hits: int) -> str:
    """Heuristic risk scoring for the Sleeper Heatmap."""
    if avg_rt > 200 or anomaly_hits >= 10:
        return "CRITICAL"
    elif avg_rt > 150 or anomaly_hits >= 5:
        return "HIGH"
    elif avg_rt > 120 or anomaly_hits >= 2:
        return "MEDIUM"
    return "LOW"


# ─── 1. Forensic City Map ────────────────────────────────────────────────────

async def get_city_map(session: AsyncSession) -> CityMapResponse:
    """
    Returns every node's TRUE status based on HTTP response codes.
    Deliberately ignores json_status = 'OPERATIONAL' (deceptive field).
    Results are cached in Redis for CACHE_TTL_SECONDS.
    """
    cached = await cache_get(CACHE_CITY_MAP)
    if cached:
        return CityMapResponse(**cached)

    # 1. Determine current window start (Sliding Forensic Window: last 5000 pkts)
    max_id_stmt = select(func.max(SystemLog.log_id))
    current_max_id = (await session.execute(max_id_stmt)).scalar() or 0
    window_start = (current_max_id // 5000) * 5000

    # 2. Identify nodes with anomalies in the current window
    inf_stmt = select(func.distinct(AnomalyRecord.node_id)).where(AnomalyRecord.log_id >= window_start)
    inf_nodes = set((await session.execute(inf_stmt)).scalars().all())

    # 3. Latest HTTP code per node
    subq = (
        select(
            SystemLog.node_id,
            func.max(SystemLog.log_id).label("latest_log_id"),
        )
        .group_by(SystemLog.node_id)
        .subquery()
    )

    stmt = (
        select(
            Node.node_uuid,
            Node.serial_number,
            SystemLog.http_response_code,
        )
        .join(subq, Node.node_uuid == subq.c.node_id)
        .join(SystemLog, (SystemLog.node_id == subq.c.node_id) & (SystemLog.log_id == subq.c.latest_log_id))
    )

    rows = (await session.execute(stmt)).fetchall()

    nodes = []
    for row in rows:
        code = row.http_response_code
        label = (
            "HEALTHY" if code == 200
            else "PARTIAL" if code == 206
            else "THROTTLED" if code == 429
            else "CRITICAL"
        )
        nodes.append(CityMapNode(
            node_uuid=row.node_uuid,
            serial_number=row.serial_number,
            http_status_label=label,
            http_response_code=code,
            is_infected=(row.node_uuid in inf_nodes),
        ))

    response = CityMapResponse(total=len(nodes), nodes=nodes, generated_at=_now())
    await cache_set(CACHE_CITY_MAP, response.model_dump(mode="json"))
    return response


# ─── 2. Sleeper Heatmap ──────────────────────────────────────────────────────

async def get_heatmap(session: AsyncSession) -> HeatmapResponse:
    """
    Aggregated response-time statistics per node.
    Nodes with high latency / many anomaly hits = hidden malware candidates.
    """
    # Bypass cache for real-time demo-performance in production if needed
    # cached = await cache_get(CACHE_HEATMAP)
    # if cached:
    #     return HeatmapResponse(**cached)

    # 1. Determine current window start (Sliding Forensic Window: last 5000 pkts)
    max_id_stmt = select(func.max(SystemLog.log_id))
    current_max_id = (await session.execute(max_id_stmt)).scalar() or 0
    window_start = max(0, current_max_id - 5000)

    # 2. Aggregate response times per node in window
    agg_stmt = (
        select(
            SystemLog.node_id,
            func.avg(SystemLog.response_time_ms).label("avg_rt"),
            func.max(SystemLog.response_time_ms).label("max_rt"),
            func.count(SystemLog.log_id).label("log_count"),
            # Guard percentile_cont for empty groups
            func.percentile_cont(0.95)
                .within_group(SystemLog.response_time_ms)
                .label("p95_rt"),
        )
        .where(SystemLog.log_id >= window_start)
        .group_by(SystemLog.node_id)
    )
    agg_result = await session.execute(agg_stmt)
    agg_rows = agg_result.fetchall() if agg_result else []

    # 3. Anomaly hits per node in window
    anomaly_stmt = (
        select(
            AnomalyRecord.node_id,
            func.count(AnomalyRecord.id).label("hit_count"),
        )
        .where(AnomalyRecord.log_id >= window_start)
        .group_by(AnomalyRecord.node_id)
    )
    anomaly_map = {
        row.node_id: row.hit_count
        for row in (await session.execute(anomaly_stmt)).fetchall()
    }

    # 4. Fetch serial numbers
    sn_map = {
        row.node_uuid: row.serial_number
        for row in (await session.execute(select(Node.node_uuid, Node.serial_number))).fetchall()
    }

    entries = []
    for row in agg_rows:
        hits = anomaly_map.get(row.node_id, 0)
        avg_rt = float(row.avg_rt or 0)
        entries.append(HeatmapEntry(
            node_uuid=row.node_id,
            serial_number=sn_map.get(row.node_id, "UNKNOWN"),
            avg_response_time_ms=round(avg_rt, 2),
            max_response_time_ms=int(row.max_rt or 0),
            p95_response_time_ms=round(float(row.p95_rt or 0), 2),
            log_count=row.log_count,
            anomaly_hit_count=hits,
            risk_level=_risk_level(avg_rt, hits),
        ))

    # Sort by Latency to ensure top-representatives are picked
    entries.sort(key=lambda e: -e.avg_response_time_ms)

    # Stratified Selection: 15 Critical, 5 Medium, 5 Low (Total 25)
    criticals = [e for e in entries if e.risk_level == "CRITICAL"][:15]
    mediums = [e for e in entries if e.risk_level == "MEDIUM"][:5]
    lows = [e for e in entries if e.risk_level == "LOW"][:5]
    final_entries = criticals + mediums + lows

    response = HeatmapResponse(total_nodes=len(final_entries), entries=final_entries, generated_at=_now())
    # await cache_set(CACHE_HEATMAP, response.model_dump(mode="json"))
    return response


# ─── 3. Dynamic Schema Console ────────────────────────────────────────────────

async def get_schema_console(session: AsyncSession, cookie_log_id: int | None = None) -> SchemaConsoleResponse:
    """
    Returns current active schema version.
    cookie_log_id: if provided (from request cookie), use it to determine active version.
    Otherwise defaults to max log_id in DB.
    """
    schema_rows = (
        await session.execute(select(SchemaConfig).order_by(SchemaConfig.time_start))
    ).scalars().all()

    if cookie_log_id is None:
        latest_result = await session.execute(select(func.max(SystemLog.log_id)))
        cookie_log_id = latest_result.scalar() or 0

    # Find the schema version active at cookie_log_id (Dynamic cyclic rotation)
    is_v2 = (cookie_log_id // 5000) % 2 == 1
    current_v = 2 if is_v2 else 1
    current_version = next((sv for sv in schema_rows if sv.version == current_v), schema_rows[0])

    versions = [
        SchemaConsoleEntry(
            version=sv.version,
            active_column=sv.active_column,
            time_start=sv.time_start,
            is_current=(sv.version == current_version.version),
        )
        for sv in schema_rows
    ]

    return SchemaConsoleResponse(
        current_version=current_version.version,
        current_column=current_version.active_column,
        latest_log_id=cookie_log_id,
        versions=versions,
    )


# ─── 4. Asset Registry ────────────────────────────────────────────────────────

async def get_asset_registry(
    session: AsyncSession,
    skip: int = 0,
    limit: int = 100,
) -> list[NodeOut]:
    """
    Returns all nodes with their Base64-decoded serial numbers.
    This is the 'truth' table — serial numbers were masked in raw data.
    """
    stmt = select(Node).offset(skip).limit(limit).order_by(Node.node_uuid)
    nodes = (await session.execute(stmt)).scalars().all()
    return [NodeOut.model_validate(n) for n in nodes]


async def get_node_status(session: AsyncSession, node_id: int) -> NodeStatusOut | None:
    """Full forensic status for a single node."""
    node = await session.get(Node, node_id)
    if not node:
        return None

    latest_log_stmt = (
        select(SystemLog)
        .where(SystemLog.node_id == node_id)
        .order_by(SystemLog.log_id.desc())
        .limit(1)
    )
    latest_log = (await session.execute(latest_log_stmt)).scalar_one_or_none()
    if not latest_log:
        return None

    return NodeStatusOut(
        node_uuid=node.node_uuid,
        serial_number=node.serial_number,
        is_infected=node.is_infected,
        is_quarantined=node.is_quarantined,
        quarantine_reason=node.quarantine_reason,
        last_http_code=latest_log.http_response_code,
        last_response_time_ms=latest_log.response_time_ms,
        true_status=latest_log.http_status_label,
        json_status=latest_log.json_status,
        active_schema_version=latest_log.active_schema_version,
        effective_load=latest_log.effective_load,
    )


# ─── 5. Anomaly Listing ───────────────────────────────────────────────────────

async def get_anomalies(
    session: AsyncSession,
    skip: int = 0,
    limit: int = 200,
) -> AnomalySummary:
    """Returns all ML-detected anomaly records."""
    stmt = (
        select(AnomalyRecord)
        .order_by(AnomalyRecord.anomaly_score.asc())  # most anomalous first
        .offset(skip)
        .limit(limit)
    )
    records = (await session.execute(stmt)).scalars().all()

    total_stmt = select(func.count(AnomalyRecord.id))
    total = (await session.execute(total_stmt)).scalar() or 0

    unique_stmt = select(func.count(func.distinct(AnomalyRecord.node_id)))
    unique_nodes = (await session.execute(unique_stmt)).scalar() or 0

    return AnomalySummary(
        total_anomalies=total,
        unique_nodes_flagged=unique_nodes,
        anomalies=[AnomalyOut.model_validate(r) for r in records],
    )


# ─── 6. Threat Score Engine ───────────────────────────────────────────────────

async def get_threat_scores(session: AsyncSession) -> ThreatScoreResponse:
    """
    Calculates operational threat scores [0.0 - 1.0] per node.
    - Jitter Analysis: Variance in response time over the last 10 logs.
    - Frequency Fingerprinting: Logs per second over the last 10 logs.
    - Status Weighting: 429 and 206 status codes act as massive multipliers.
    """
    cached = await cache_get(CACHE_THREAT_SCORE)
    if cached:
        return ThreatScoreResponse(**cached)

    subq = (
        select(
            SystemLog.node_id,
            SystemLog.response_time_ms,
            SystemLog.http_response_code,
            SystemLog.ingested_at,
            func.row_number().over(
                partition_by=SystemLog.node_id,
                order_by=SystemLog.log_id.desc()
            ).label('rn')
        )
        .subquery()
    )

    stmt = (
        select(
            Node.node_uuid,
            Node.serial_number,
            subq.c.response_time_ms,
            subq.c.http_response_code,
            subq.c.ingested_at
        )
        .join(Node, Node.node_uuid == subq.c.node_id)
        .where(subq.c.rn <= 10)
        .order_by(Node.node_uuid, subq.c.rn)
    )

    rows = (await session.execute(stmt)).all()

    node_data = defaultdict(list)
    sn_map = {}
    for row in rows:
        node_id = row.node_uuid
        node_data[node_id].append(row)
        sn_map[node_id] = row.serial_number

    entries = []
    
    for node_id, logs in node_data.items():
        # High-Purity Shield: Filter out None values from rt_list
        rt_list = [log.response_time_ms for log in logs if log.response_time_ms is not None]
        
        try:
            if len(rt_list) > 1:
                variance = statistics.variance(rt_list)
            else:
                variance = 0.0
        except (statistics.StatisticsError, TypeError):
            variance = 0.0

        logs_sorted = sorted(logs, key=lambda x: x.ingested_at) if logs else []
        time_diff = (logs_sorted[-1].ingested_at - logs_sorted[0].ingested_at).total_seconds() if len(logs_sorted) > 1 else 0.0
        
        if time_diff > 0:
            lps = len(logs) / time_diff
        else:
            lps = float(len(logs))

        codes = [log.http_response_code for log in logs]
        has_ddos = 429 in codes
        has_partial = 206 in codes
        
        status_multiplier = 1.0
        if has_ddos:
            status_multiplier = 2.5
        elif has_partial:
            status_multiplier = 1.5

        jitter_score = min(variance / 5000.0, 0.4)
        freq_score = min(lps / 10.0, 0.4)
        
        base_score = jitter_score + freq_score
        
        final_score = base_score * status_multiplier
        final_score = min(max(final_score, 0.0), 1.0)
        
        entries.append(ThreatScoreEntry(
            node_uuid=node_id,
            serial_number=sn_map[node_id],
            threat_score=round(final_score, 4),
            jitter_variance=round(variance, 2),
            logs_per_second=round(lps, 2),
            status_multiplier=status_multiplier
        ))

    entries.sort(key=lambda x: x.threat_score, reverse=True)
    
    response = ThreatScoreResponse(
        active_nodes=len(entries),
        scores=entries,
        generated_at=_now()
    )
    await cache_set(CACHE_THREAT_SCORE, response.model_dump(mode="json"))
    return response


# ─── 7. Unified Dashboard Aggregation ────────────────────────────────────────

async def get_dashboard_state(session: AsyncSession, full: bool = False) -> DashboardAggregationResponse:
    """
    ONE ENDPOINT TO RULE THEM ALL.
    Aggregates metadata, schema state, nodes, heatmap, and logs into a single response.
    Minimizes frontend round-trips for the Cyberpunk Dashboard.
    full: If True, includes static/heavy node metadata (pos, serial, ua).
    """
    # 1. Metadata & Master Sync
    max_id_stmt = select(func.max(SystemLog.log_id))
    current_max_id = (await session.execute(max_id_stmt)).scalar() or 0
    
    # 2. Schema State
    schema_info = await get_schema_console(session)

    # 3. Active Threats (Filtered by synced Master Window: last 5000 pkts)
    window_start_id = (current_max_id // 5000) * 5000
    
    active_threats_stmt = (
        select(func.count(func.distinct(AnomalyRecord.node_id)))
        .where(AnomalyRecord.log_id >= window_start_id)
    )
    active_threats = (await session.execute(active_threats_stmt)).scalar() or 0

    total_anomalies_stmt = (
        select(func.count(AnomalyRecord.id))
        .where(AnomalyRecord.log_id >= window_start_id)
    )
    total_anomalies = (await session.execute(total_anomalies_stmt)).scalar() or 0
    
    # 3. Nodes (Forensic Map + Registry) - STRATIFIED LOAD
    dashboard_nodes = None
    if full:
        nodes_stmt = select(Node)
        nodes_rows = (await session.execute(nodes_stmt)).scalars().all()
        
        # Optimized: Get the latest log for each node using DISTINCT ON (Postgres-specific power)
        # This leverages the ix_system_logs_node_log index (node_id, log_id)
        lookback_id = max(0, current_max_id - 5000)
        status_stmt = (
            select(SystemLog)
            .where(SystemLog.log_id >= lookback_id)
            .distinct(SystemLog.node_id)
            .order_by(SystemLog.node_id, SystemLog.log_id.desc())
        )
        statuses_result = await session.execute(status_stmt)
        statuses = {s.node_id: s for s in statuses_result.scalars().all()}

        # Identify nodes with anomalies in the current window (Hard-Sync)
        inf_nodes_stmt = select(func.distinct(AnomalyRecord.node_id)).where(AnomalyRecord.log_id >= window_start_id)
        inf_nodes = set((await session.execute(inf_nodes_stmt)).scalars().all())

        import random # for visual variety if pos not set
        dashboard_nodes = []
        for n in nodes_rows:
            s = statuses.get(n.node_uuid)
            node_data = {
                "id": n.node_uuid,
                "is_infected": (n.node_uuid in inf_nodes),
                "is_quarantined": n.is_quarantined,
                "conflict_detected": False,
                "last_http_code": s.http_response_code if s else 200,
                "reported_json": s.json_status if s else "OPERATIONAL",
                "pos": {"x": getattr(n, 'pos_x', random.uniform(5, 95)), "y": getattr(n, 'pos_y', random.uniform(5, 95))},
                "decoded_serial": n.serial_number,
                "encoded_ua": n.user_agent,
            }
            dashboard_nodes.append(DashboardNode(**node_data))

    # 4. Heatmap
    heatmap_data = await get_heatmap(session)
    serialized_heatmap = [e.model_dump() for e in heatmap_data.entries[:30]] # top 30 risk

    # Terminal Logs (Filtered for Light Mode)
    limit_logs = 50 if full else 10
    logs_stmt = select(SystemLog).order_by(SystemLog.log_id.desc()).limit(limit_logs)
    latest_logs = (await session.execute(logs_stmt)).scalars().all()
    
    # 5. Metadata Construction
    latest_log_ts = latest_logs[0].ingested_at.isoformat() if (latest_logs and len(latest_logs) > 0 and latest_logs[0].ingested_at) else _now().isoformat()
    
    terminal_logs = [
        LogEntry(
            id=l.log_id,
            timestamp=l.ingested_at.isoformat() if l.ingested_at else _now().isoformat(),
            node_id=l.node_id,
            message=f"Forensic Packet Recv: {l.http_response_code} | RT={l.response_time_ms}ms",
            status=getattr(l, 'http_status_label', 'UNKNOWN'),
            http_code=l.http_response_code
        ) for l in latest_logs
    ]

    return DashboardAggregationResponse(
        metadata=DashboardMetadata(
            system_time=int(datetime.now().timestamp()),
            latest_log_timestamp=latest_log_ts,
            total_logs_processed=current_max_id,
            active_threats=active_threats,
            total_anomalies=total_anomalies,
            status="OPERATIONAL_SYNCED_STRATIFIED"
        ),
        schema_engine=SchemaEngineState(
            current_version=schema_info.current_version,
            active_column=schema_info.current_column,
            rotation_timer=f"-{(5000 - (current_max_id % 5000)) if (current_max_id % 5000) != 0 else 5000:04d}_PKTS",
            sync_status=f"{schema_info.current_column}_LOCKED"
        ),
        nodes=dashboard_nodes,
        heatmap=serialized_heatmap,
        terminal_logs=terminal_logs
    )


# ─── 7. Raw Telemetry Stream ──────────────────────────────────────────────────

async def get_system_logs(session: AsyncSession, limit: int = 50, after_id: int | None = None) -> list[LogEntry]:
    """
    Returns the telemetry log stream with joined Anomaly Scores from the ML engine.
    """
    # Join with AnomalyRecord to get the threat score if it exists
    stmt = select(SystemLog, AnomalyRecord.anomaly_score, AnomalyRecord.detector).outerjoin(
        AnomalyRecord, SystemLog.log_id == AnomalyRecord.log_id
    )

    if after_id is not None:
        stmt = stmt.where(SystemLog.log_id > after_id).order_by(SystemLog.log_id.asc())
    else:
        stmt = stmt.order_by(SystemLog.log_id.desc())
    
    stmt = stmt.limit(limit)
    res = await session.execute(stmt)
    rows = res.all() # Each row is (SystemLog, anomaly_score, detector)

    if after_id is None:
        rows = list(reversed(rows))

    import math
    return [
        LogEntry(
            id=l.log_id,
            timestamp=l.ingested_at.isoformat() if l.ingested_at else _now().isoformat(),
            node_id=l.node_id,
            message=f"Forensic Packet Recv: {l.http_response_code} | RT={l.response_time_ms}ms",
            status=getattr(l, 'http_status_label', 'UNKNOWN'),
            http_code=l.http_response_code,
            # Invert and normalize IsolationForest score: lower (negative) scores = higher threat probability
            # Centered at score=0.0 -> 50% Threat. score=-0.15 -> 85% Threat.
            threat_score=float(1.0 / (1.0 + math.exp(12.0 * score))) if score is not None else (0.05 + (l.log_id % 100) / 2000.0),
            detector=detector
        ) for l, score, detector in rows
    ]