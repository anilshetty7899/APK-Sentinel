"""APK Sentinel — FastAPI Application.

Main application entry point with CORS, lifespan management, and routing.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers.analyses import router as analyses_router
from app.schemas import HealthResponse
from app.utils.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB on startup."""
    logger.info("APK Sentinel starting up…")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("APK Sentinel shutting down…")


app = FastAPI(
    title="APK Sentinel",
    description="AI-assisted Android APK static security analysis platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(analyses_router)


@app.get("/api/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="ok", version="0.1.0")
