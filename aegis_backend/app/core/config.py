"""
app/core/config.py
Central configuration — reads from environment / .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # --- App ---
    APP_NAME: str = "AEGIS Defense System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # --- PostgreSQL ---
    # Railway/Render provide DATABASE_URL. If set, this overrides decomposed vars.
    DATABASE_URL: str | None = None
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegis"
    POSTGRES_PASSWORD: str = "aegis_secret"
    POSTGRES_DB: str = "aegis_db"

    def get_database_url(self, async_mode: bool = True) -> str:
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            for scheme in ["postgresql://", "postgres://"]:
                if url.startswith(scheme):
                    driver = "+asyncpg://" if async_mode else "+psycopg2://"
                    return url.replace(scheme, f"postgresql{driver}", 1)
            return url
        
        driver = "asyncpg" if async_mode else "psycopg2"
        return (
            f"postgresql+{driver}://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def ASYNC_DATABASE_URL(self) -> str:
        return self.get_database_url(async_mode=True)

    @property
    def DATABASE_URL_STR(self) -> str:
        return self.get_database_url(async_mode=True)

    @property
    def SYNC_DATABASE_URL(self) -> str:
        return self.get_database_url(async_mode=False)

    # --- Redis ---
    # Railway provides REDIS_URL. If set, overrides host/port.
    REDIS_URL: str | None = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    CACHE_TTL_SECONDS: int = 30

    # --- ML ---
    MODEL_PATH: str = "data/models/anomaly_detector.joblib"
    ISOLATION_FOREST_CONTAMINATION: float = 0.08  # ~8% of nodes are infected per data
    ANOMALY_THRESHOLD: float = 0.0                # IsolationForest: score < 0 = anomaly (model's own convention)

    # --- Data ---
    NODE_REGISTRY_PATH: str = "data/node_registry.csv"
    SYSTEM_LOGS_PATH: str = "data/system_logs.csv"
    SCHEMA_CONFIG_PATH: str = "data/schema_config.csv"

    # --- Schema rotation boundary (from schema_config) ---
    SCHEMA_ROTATION_LOG_ID: int = 5000


@lru_cache
def get_settings() -> Settings:
    return Settings()