"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Response schemas ──────────────────────────────────────────────────


class AnalysisCreated(BaseModel):
    """Returned after a successful APK upload."""
    id: str
    sha256: str
    original_filename: str
    file_size: int
    status: str
    created_at: datetime


class AnalysisStatus(BaseModel):
    """Current status of an analysis."""
    id: str
    sha256: str
    original_filename: str
    file_size: int
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    error_message: Optional[str] = None
    progress_percent: int = 0
    progress_stage: str = "Queued"
    progress_tasks: List[Dict[str, str]] = Field(default_factory=list)
    dynamic_requested: bool = False
    dynamic_status: str = "NOT_REQUESTED"
    dynamic_error: Optional[str] = None


class AnalysisSummary(BaseModel):
    """Compact view for listing analyses."""
    id: str
    sha256: str
    original_filename: str
    file_size: int
    status: str
    created_at: datetime
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


class AnalysisListResponse(BaseModel):
    """Paginated list of analyses."""
    items: List[AnalysisSummary]
    total: int


class AnalysisResults(BaseModel):
    """Structured analysis findings."""
    id: str
    status: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    results: Optional[Dict[str, Any]] = None


class AnalysisReport(BaseModel):
    """AI-generated security report."""
    id: str
    status: str
    ai_report: Optional[Dict[str, Any]] = None
    report_available: bool = False


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = "0.1.0"
    dynamic_analysis_available: bool = False
    dynamic_analysis_configured: bool = False


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
