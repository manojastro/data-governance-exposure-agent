"""Application configuration via pydantic-settings.

DATABASE_URL defaults to a SQLite file under <project>/data. Relative SQLite
paths are anchored at the project root (the parent of backend/) so the same
database is used no matter which directory the server or scripts run from.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> parents[2] is the project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]

_SECRETS = {"LLM_API_KEY"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Data Access Governance & Sensitive Data Exposure Agent"
    APP_VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./data/data_governance.db"

    LLM_MODE: str = "mock"  # mock | openai-compatible
    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""
    LLM_MODEL: str = ""

    CORS_ORIGINS: str = "*"  # comma-separated list, or "*"
    LOG_LEVEL: str = "INFO"
    ADAPTER: str = "local"  # local | snowflake | unity | lakeformation | purview

    STALE_DAYS: int = 90
    CLASSIFICATION_COVERAGE_TARGET: float = 0.95

    def cors_origin_list(self) -> list[str]:
        raw = self.CORS_ORIGINS.strip()
        if raw in ("", "*"):
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def resolve_database_url(url: str) -> str:
    """Anchor relative SQLite paths at the project root."""
    if url.startswith("sqlite:///"):
        path_part = url[len("sqlite:///"):]
        p = Path(path_part)
        if not p.is_absolute():
            p = (PROJECT_ROOT / path_part).resolve()
            return "sqlite:///" + str(p).replace("\\", "/")
    return url


def mask_secrets(data: dict) -> dict:
    """Return a copy of dict with known secret keys redacted."""
    out = {}
    for k, v in data.items():
        out[k] = "***" if k.upper() in _SECRETS and v else v
    return out
