"""
aegis_backend/scripts/calibrate_sequences.py
Mission Sequence Calibration for AEGIS Defense System.
"""
import asyncio
import logging
import os
import sys
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Add parent directory to path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.calibrate")

async def calibrate():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        logger.error("DATABASE_URL not found in environment.")
        return

    # Standardize scheme for asyncpg
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    # SSL Intelligence: Only force SSL if NOT on local machine or standard Docker network
    connect_args = {}
    if all(h not in database_url for h in ["localhost", "127.0.0.1", "postgres"]):
        connect_args["ssl"] = True

    engine = create_async_engine(database_url, connect_args=connect_args)

    logger.info("Initiating AEGIS Sequence Calibration...")
    
    async with engine.begin() as conn:
        # Calibrate system_logs
        await conn.execute(text("SELECT setval('system_logs_log_id_seq', (SELECT MAX(log_id) FROM system_logs))"))
        logger.info("→ system_logs sequence calibrated.")
        
        # Calibrate anomaly_records
        await conn.execute(text("SELECT setval('anomaly_records_id_seq', (SELECT MAX(id) FROM anomaly_records))"))
        logger.info("→ anomaly_records sequence calibrated.")
        
    logger.info("MISSION SEQUENCES SYNCHRONIZED. The autonomous pulse is now clear for takeoff.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(calibrate())
