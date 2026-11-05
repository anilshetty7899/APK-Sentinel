"""Application configuration via pydantic-settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"

    # Groq AI
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    # Optional VirusTotal hash-only reputation lookup. APK bytes are never
    # submitted by this integration.
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_LOOKUP_ENABLED: bool = False

    # Upload constraints
    MAX_APK_SIZE_MB: int = 100

    # Analysis
    ANALYSIS_TIMEOUT_SECONDS: int = 900
    UPLOAD_DIR: str = "./uploads"
    ANALYSIS_DIR: str = "./analysis_data"
    # Absolute path as seen by the Docker daemon (distinct from the backend
    # container path when the API itself runs in Docker Compose).
    ANALYSIS_HOST_DIR: str = ""
    ANALYZER_IMAGE: str = "apk-sentinel-analyzer:latest"
    ANALYZER_MEM_LIMIT: str = "512m"
    ANALYZER_CPU_PERIOD: int = 100000
    ANALYZER_CPU_QUOTA: int = 50000  # 50% of one core

    # CORS
    CORS_ORIGINS: str = '["http://localhost:5173"]'

    @property
    def max_apk_size_bytes(self) -> int:
        return self.MAX_APK_SIZE_MB * 1024 * 1024

    @property
    def cors_origins_list(self) -> List[str]:
        return json.loads(self.CORS_ORIGINS)

    @property
    def upload_path(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def analysis_path(self) -> Path:
        p = Path(self.ANALYSIS_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def analysis_host_path(self) -> Path:
        return Path(self.ANALYSIS_HOST_DIR) if self.ANALYSIS_HOST_DIR else self.analysis_path


settings = Settings()
