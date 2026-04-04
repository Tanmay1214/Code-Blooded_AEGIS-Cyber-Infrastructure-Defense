"""
main.py
FastAPI application entry point.
Handles startup (DB tables, model loading) and shutdown.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import create_all_tables
from app.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("aegis.main")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    # ── Startup ──────────────────────────────────────────────
    logger.info("AEGIS Backend starting up...")

    # Create DB tables (idempotent) — graceful degradation if DB unavailable
    try:
        await create_all_tables()
        logger.info("Database tables ready")
        app.state.db_available = True
    except Exception as e:
        logger.warning("DB unavailable at startup — fallback mode. Error: %s", e)
        app.state.db_available = False

    # Load trained ML models
    try:
        from app.ml.detector import load_models
        app.state.models = load_models()
        logger.info("ML models loaded successfully")
    except FileNotFoundError as e:
        logger.warning("ML models not found — inference disabled. Run train_model.py. (%s)", e)
        app.state.models = None

    # Launch autonomous forensic services
    from app.services.pulse import forensic_autonomous_pulse, forensic_quarantine_watchdog
    import asyncio
    asyncio.create_task(forensic_autonomous_pulse(app))
    asyncio.create_task(forensic_quarantine_watchdog())

    yield  # ── Application is running ───────────────────────

    # ── Shutdown ─────────────────────────────────────────────
    logger.info("AEGIS Backend shutting down...")
    try:
        from app.core.cache import get_redis
        await get_redis().aclose()
    except Exception:
        pass


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "AEGIS Cyber-Infrastructure Defense System — "
            "real-time anomaly detection, forensic node mapping, "
            "and schema-aware telemetry analysis for Nexus City."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health-check")
    async def health_check():
        return {"status": "operational", "version": settings.APP_VERSION}

    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)