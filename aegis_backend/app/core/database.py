"""
app/core/database.py
Async SQLAlchemy engine + session factory.
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import get_settings

settings = get_settings()

# Standard asyncpg SSL logic for production (Render/Managed DB)
connect_args = {}
# Only force SSL if NOT running on localhost or inside the standard Docker 'postgres' network
if all(h not in settings.DATABASE_URL_STR for h in ["localhost", "127.0.0.1", "postgres"]):
    connect_args["ssl"] = True

engine = create_async_engine(
    settings.DATABASE_URL_STR,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_all_tables():
    """Create all tables on startup with a retry loop to handle transient cloud DNS failures."""
    import asyncio
    import logging
    logger = logging.getLogger("aegis.db")
    
    # Redacted URL for debugging
    from urllib.parse import urlparse
    parsed = urlparse(settings.DATABASE_URL_STR)
    host = parsed.hostname or "unknown-host"
    port = parsed.port or 5432
    redacted_host = f"{host}:{port}"
    
    max_retries = 5
    for attempt in range(1, max_retries + 1):
        logger.info("[FINAL STRIKE] Handshake Attempt %d/%d to host: %s", attempt, max_retries, redacted_host)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables verified successfully.")
            return
        except Exception as e:
            if attempt == max_retries:
                logger.error("Final database connection attempt failed: %s", e)
                raise
            logger.warning("Database connection attempt %d/%d failed (DNS/Handshake). Retrying in 5s... Error: %s", attempt, max_retries, e)
            await asyncio.sleep(5)