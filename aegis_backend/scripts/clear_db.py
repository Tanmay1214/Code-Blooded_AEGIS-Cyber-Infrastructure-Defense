"""
aegis_backend/scripts/clear_db.py
Surgical database wipe for AEGIS Mission Reset.
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
logger = logging.getLogger("aegis.wipe")

async def clear_database():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        logger.error("DATABASE_URL not found in environment.")
        return

    # Standardize scheme for asyncpg
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    # SSL for Render
    connect_args = {"ssl": True} if "localhost" not in database_url else {}

    engine = create_async_engine(database_url, connect_args=connect_args)

    logger.info("Initiating AEGIS Forensic Wipe...")
    
    tables_to_drop = [
        "anomaly_records",
        "system_logs",
        "node_registry",
        "schema_configs",
        "alembic_version"
    ]

    async with engine.begin() as conn:
        for table in tables_to_drop:
            logger.info(f"Dropping table: {table}")
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
        
        logger.info("Resetting Mission Sequences...")
        # (Sequences are dropped with tables, so they recreate on next startup)
        
    logger.info("DATABASE WIPE SUCCESSFUL. Mission sectors are now 100% clean.")
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(clear_database())
