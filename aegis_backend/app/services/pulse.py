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
from app.models.orm import SystemLog, AnomalyRecord
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
    # Pre-calculate schema rotation boundary
    rotation_id = settings.SCHEMA_ROTATION_LOG_ID # 5000

    while True:
        try:
            # Batch size 50 every 2 seconds (~25 pkts/sec) to stay within free-tier limits
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
                # (Mirroring the logic in routes.py:188)
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
                    # We inject effective_load for the ML scoring helper, 
                    # even though it's not a DB column (we'll pop it before insert)
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
                    # Adapt data for score_log_batch
                    # It expects objects with .response_time_ms, .http_response_code, .effective_load
                    class MockLog:
                        def __init__(self, d):
                            self.response_time_ms = d["response_time_ms"]
                            self.http_response_code = d["http_response_code"]
                            self.effective_load = d["_eff_load"]
                    
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
                    
                    if anomaly_records:
                        stmt_anom = pg_insert(AnomalyRecord).values(anomaly_records)
                        await session.execute(stmt_anom)
                
                await session.commit()
            
            if iteration % 20 == 0:
                logger.info("AUTONOMOUS_PULSE_SYNC [%06d]: Batch commit successful. (Total Logs: %d)", 
                            iteration * batch_size, current_max_id + batch_size)
            
        except Exception as e:
            logger.error("AUTONOMOUS_PULSE_GLITCH: %s", e)
            await asyncio.sleep(10) # Heavy backoff on error

        iteration += 1
        await asyncio.sleep(2.0) # Cadence: 25 logs/sec (Conservative for Free Tier)

