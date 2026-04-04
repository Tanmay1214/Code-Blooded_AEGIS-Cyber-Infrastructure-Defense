"""
aegis_backend/app/services/pulse.py
Autonomous background telemetry engine for zero-cost cloud automation.
"""
import asyncio
import logging
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.database import AsyncSessionLocal
from app.models.orm import SystemLog, AnomalyRecord, Node, QuarantineLog
from app.core.config import get_settings

logger = logging.getLogger("aegis.pulse")
settings = get_settings()

async def forensic_autonomous_pulse(app):
    """
    AEGIS Autonomous Pulse Engine.
    Bypasses HTTP overhead by injecting telemetry directly into the persistence layer.
    """
    from app.ml.detector import score_log_batch

    logger.info("AUTONOMOUS_PULSE_INITIALIZING")

    # ── PATH RESOLUTION ──
    # Try CWD-relative first (uvicorn launched from aegis_backend dir, so path is ASCII-safe)
    csv_path = Path("data/system_logs.csv")
    if not csv_path.exists():
        # Absolute fallback
        csv_path = Path(__file__).resolve().parent.parent.parent / "data" / "system_logs.csv"

    if not csv_path.exists():
        logger.error("AUTONOMOUS_PULSE_FAILED: system_logs.csv not found")
        return

    try:
        logger.info("AUTONOMOUS_PULSE_LOADING: %s", csv_path.name)

        def load_csv_guarded(path):
            with open(path, mode='r', encoding='utf-8', errors='ignore') as f:
                return pd.read_csv(f)

        df_logs = await asyncio.to_thread(load_csv_guarded, csv_path)
        total_csv_logs = len(df_logs)
        logger.info("AUTONOMOUS_PULSE_LOADED: %d records ready.", total_csv_logs)
    except Exception as e:
        logger.error("AUTONOMOUS_PULSE_STALL: %s: %s", type(e).__name__, e)
        return

    iteration = 0
    consecutive_failures = 0
    rotation_id = settings.SCHEMA_ROTATION_LOG_ID

    logger.info("AUTONOMOUS_PULSE_RUNNING")
    while True:
        try:
            # Slower ingestion for realistic simulation and to prevent 2000 logs/request bursts
            batch_size = 5
            batch_data = []
            
            # Determine current log_id offset 
            async with AsyncSessionLocal() as session:
                max_id_res = await session.execute(select(func.max(SystemLog.log_id)))
                current_max_id = (max_id_res.scalar() or 0)
            
                # ── COLLECT BATCH (Off-Grid) ──
                for i in range(batch_size):
                    idx = (iteration * batch_size + i) % total_csv_logs
                    row = df_logs.iloc[idx]
                    
                    est_id = current_max_id + i + 1
                    is_v2 = (est_id // 5000) % 2 == 1
                    
                    l_v1_val = float(row.get('L_V1', 0.0)) if pd.notnull(row.get('L_V1')) else 0.0
                    load_val = float(row.get('load_val', 0.0)) if pd.notnull(row.get('load_val')) else 0.0
                    eff_load = l_v1_val if is_v2 else load_val

                    batch_data.append({
                        "node_id": int(row['node_id']),
                        "json_status": str(row['json_status']),
                        "http_response_code": int(row['http_response_code']),
                        "response_time_ms": int(row.get('response_time_ms', 0)),
                        "load_val": load_val,
                        "L_V1": l_v1_val,
                        "_eff_load": eff_load
                    })
                
                # ── AEGIS ATOMIC REGISTRY ──
                # node_uuid is the PK on the Node table; SystemLog.node_id is FK → nodes.node_uuid
                # Nodes are pre-seeded; this insert is a safety net for any unseen node_ids.
                # user_agent and serial_number are NOT NULL — provide placeholders.
                unique_node_ids = list(set(d["node_id"] for d in batch_data))
                node_sync_stmt = pg_insert(Node.__table__).values(
                    [{"node_uuid": nid, "user_agent": f"AEGIS-Node/2.0", "serial_number": f"SN-{nid}", "is_infected": False, "is_quarantined": False} for nid in unique_node_ids]
                ).on_conflict_do_nothing(index_elements=["node_uuid"])

                await session.execute(node_sync_stmt)
                await session.flush()

                # ── TELEMETRY INGESTION ──
                sql_data = [{k: v for k, v in d.items() if k != "_eff_load"} for d in batch_data]
                stmt = pg_insert(SystemLog).values(sql_data).returning(SystemLog.log_id)
                result = await session.execute(stmt)
                inserted_ids = result.scalars().all()
                
                # ── NEURAL SCORING ──
                if hasattr(app.state, "models") and app.state.models:
                    from dataclasses import dataclass
                    @dataclass
                    class MockLog:
                        response_time_ms: int
                        http_response_code: int
                        load_val: float
                        l_v1: float
                    
                    logs_for_ml = [MockLog(d["response_time_ms"], d["http_response_code"], d["load_val"], d["L_V1"]) for d in batch_data]
                    ml_results = score_log_batch(app.state.models, logs_for_ml, settings.ANOMALY_THRESHOLD)
                    
                    anomaly_records = []
                    for k, (is_anomaly, score) in enumerate(ml_results):
                        if is_anomaly:
                            log_id = inserted_ids[k] if k < len(inserted_ids) else None
                            if log_id:
                                anomaly_records.append({
                                    "node_id": batch_data[k]["node_id"],
                                    "log_id": log_id,
                                    "anomaly_score": round(float(score), 6),
                                    "detector": "IsolationForest"
                                })
                            
                            node_id = batch_data[k]["node_id"]
                            node_res = await session.execute(select(Node).where(Node.node_uuid == node_id))
                            node = node_res.scalar_one_or_none()
                            if node:
                                node.is_infected = True
                                
                                # QUARANTINE_SWORD
                                if score > 0.8 and not node.is_quarantined:
                                    node.is_quarantined = True
                                    node.quarantine_reason = f"SWORD: score {score:.4f}"
                                    session.add(QuarantineLog(node_id=node.node_uuid, reason=node.quarantine_reason))
                                    logger.critical("[SHIELD_ENGAGED] THE SWORD isolated node %d", node_id)
                    
                    if anomaly_records:
                        await session.execute(pg_insert(AnomalyRecord).values(anomaly_records))
                
                await session.commit()
            
            iteration += 1
            if iteration % 10 == 0:
                logger.info("PULSE_HEARTBEAT | iteration=%d | total_logs=%d", iteration, current_max_id + batch_size)

            await asyncio.sleep(0.5)

        except Exception as e:
            import traceback
            error_msg = f"PULSE_GLITCH: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            print(f"[!] {error_msg}")
            consecutive_failures += 1
            backoff = min(10 * (2 ** (consecutive_failures - 1)), 60)
            await asyncio.sleep(backoff)


async def forensic_quarantine_watchdog():
    """
    AEGIS Quarantine Watchdog.
    Periodically checks the AnomalyRecord table for high-risk threats
    that may have been ingested via API (Simulator) or other vectors.
    """
    logger.info("THE_SWORD_WATCHDOG_ACTIVATED [SCAN_MODE: ACTIVE]")
    while True:
        try:
            async with AsyncSessionLocal() as session:
                # Find high-risk anomalies
                # Query nodes that need isolation based on recent high-score anomalies
                stmt = select(AnomalyRecord).where(
                    AnomalyRecord.anomaly_score > 0.8
                ).order_by(AnomalyRecord.detected_at.desc()).limit(20)
                
                res = await session.execute(stmt)
                anomalies = res.scalars().all()
                
                for anom in anomalies:
                    node = await session.get(Node, anom.node_id)
                    if node and not node.is_quarantined:
                        node.is_quarantined = True
                        node.quarantine_reason = f"WATCHDOG: Isolated via High-Risk Anomaly (score={anom.anomaly_score:.4f})"
                        q_log = QuarantineLog(
                            node_id=node.node_uuid,
                            reason=node.quarantine_reason
                        )
                        session.add(q_log)
                        logger.critical("[WATCHDOG_STRIKE] THE SWORD isolated node %d", node.node_uuid)
                
                await session.commit()
            
            await asyncio.sleep(1) # Scan every second for production responsiveness
        except Exception as e:
            logger.error("WATCHDOG_GLITCH [RECOVERING]: %s", e)
            await asyncio.sleep(5)

