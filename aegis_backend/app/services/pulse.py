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

    logger.info("AUTONOMOUS_PULSE_INITIALIZING [MISSION: CSV_SYNC_LOOP]")
    
    csv_path = Path("data/system_logs.csv")
    if not csv_path.exists():
        # Fallback for Docker environment if path differs
        csv_path = Path("/app/data/system_logs.csv")
    
    if not csv_path.exists():
        logger.error("AUTONOMOUS_PULSE_FAILED: system_logs.csv not found at %s", csv_path)
        return

    try:
        df_logs = pd.read_csv(csv_path)
        total_csv_logs = len(df_logs)
        logger.info("AUTONOMOUS_PULSE_LOADED: %d forensic logs ready for stream.", total_csv_logs)
    except Exception as e:
        logger.error("AUTONOMOUS_PULSE_FAILED loading CSV: %s", e)
        return

    iteration = 0
    consecutive_failures = 0
    # Pre-calculate schema rotation boundary
    rotation_id = settings.SCHEMA_ROTATION_LOG_ID # 5000

    while True:
        try:
            # Batch size 50 every 0.5s (~100 pkts/sec)
            batch_size = 50
            batch_data = []
            
            # Determine current log_id offset to handle schema rotation
            async with AsyncSessionLocal() as session:
                max_id_res = await session.execute(select(func.max(SystemLog.log_id)))
                current_max_id = (max_id_res.scalar() or 0)
            
            for i in range(batch_size):
                idx = (iteration * batch_size + i) % total_csv_logs
                row = df_logs.iloc[idx]
                
                # Dynamic Schema Logic: Resolve effective_load based on current ID
                est_id = current_max_id + i + 1
                is_v2 = (est_id // 5000) % 2 == 1
                
                eff_load = float(row['L_V1']) if is_v2 and pd.notnull(row['L_V1']) else (
                    float(row['load_val']) if pd.notnull(row['load_val']) else None
                )

                log_dict = {
                    "node_id": int(row['node_id']),
                    "json_status": str(row['json_status']),
                    "http_response_code": int(row['http_response_code']),
                    "response_time_ms": int(row['response_time_ms']),
                    "load_val": float(row['load_val']) if pd.notnull(row['load_val']) else None,
                    "l_v1": float(row['L_V1']) if pd.notnull(row['L_V1']) else None,
                    "_eff_load": eff_load 
                }
                batch_data.append(log_dict)
            
            # 1. DB Bulk Insert
            async with AsyncSessionLocal() as session:
                # Remove internal _eff_load before SQL insert
                sql_data = []
                for d in batch_data:
                    copy_d = d.copy()
                    copy_d.pop("_eff_load")
                    sql_data.append(copy_d)

                stmt = pg_insert(SystemLog).values(sql_data).returning(SystemLog.log_id)
                result = await session.execute(stmt)
                inserted_ids = result.scalars().all()
                
                # 2. ML Scoring (if models loaded)
                if hasattr(app.state, "models") and app.state.models:
                    class MockLog:
                        def __init__(self, d):
                            self.response_time_ms = d["response_time_ms"]
                            self.http_response_code = d["http_response_code"]
                            self.load_val = d["load_val"]
                            self.l_v1 = d["l_v1"]
                    
                    logs_for_ml = [MockLog(d) for d in batch_data]
                    ml_results = score_log_batch(app.state.models, logs_for_ml, settings.ANOMALY_THRESHOLD)
                    
                    anomaly_records = []
                    for k, (is_anomaly, score) in enumerate(ml_results):
                        if is_anomaly:
                            anomaly_records.append({
                                "node_id": batch_data[k]["node_id"],
                                "log_id": inserted_ids[k],
                                "anomaly_score": round(float(score), 6),
                                "detector": "IsolationForest"
                            })
                            
                            # AEGIS PHASE 3: THE SWORD (Automated Quarantine)
                            if score > 0.8:
                                node_id = batch_data[k]["node_id"]
                                # We need to update Node state — using a separate execute to be safe
                                # or just session.add(node_obj) if we fetch it.
                                # Let's fetch it for simplicity in this hackathon context.
                                node = await session.get(Node, node_id)
                                if node and not node.is_quarantined:
                                    node.is_quarantined = True
                                    node.quarantine_reason = f"THE SWORD: Isolation triggered by score {score:.4f}"
                                    q_log = QuarantineLog(
                                        node_id=node_id,
                                        reason=node.quarantine_reason
                                    )
                                    session.add(q_log)
                                    logger.critical("[SHIELD_ENGAGED] THE SWORD isolated node %d", node_id)
                    
                    if anomaly_records:
                        stmt_anom = pg_insert(AnomalyRecord).values(anomaly_records)
                        await session.execute(stmt_anom)
                
                await session.commit()
            
            # Reset failsafe counter on success
            consecutive_failures = 0
            
            if iteration % 20 == 0:
                logger.debug("AUTONOMOUS_PULSE_SYNC [%06d]: Batch commit successful.", iteration * batch_size)
            
            iteration += 1
            await asyncio.sleep(0.5) # Overclocked Cadence: 100 logs/sec

        except Exception as e:
            consecutive_failures += 1
            # Exponential Backoff: 10s, 20s, 40s, max 60s
            backoff = min(10 * (2 ** (consecutive_failures - 1)), 60)
            logger.error("AUTONOMOUS_PULSE_GLITCH [%d]: Connection refused. Retrying in %ds. Error: %s", 
                         consecutive_failures, backoff, e)
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

