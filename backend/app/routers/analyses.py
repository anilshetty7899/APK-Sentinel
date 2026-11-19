"""Analysis API endpoints.

POST   /api/analyses          — Upload APK and create analysis
GET    /api/analyses          — List analyses
GET    /api/analyses/{id}     — Get analysis status/metadata
GET    /api/analyses/{id}/results  — Get structured findings
GET    /api/analyses/{id}/report   — Get AI report
DELETE /api/analyses/{id}     — Delete analysis
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Analysis, AnalysisStatus
from app.schemas import (
    AnalysisCreated,
    AnalysisListResponse,
    AnalysisReport,
    AnalysisResults,
    AnalysisStatus as AnalysisStatusSchema,
    AnalysisSummary,
)
from app.services.analyzer import job_service
from app.services.upload import UploadValidationError, cleanup_workspace, validate_and_store_apk
from app.utils.logging import logger

router = APIRouter(prefix="/api/analyses", tags=["analyses"])


@router.post("", response_model=AnalysisCreated, status_code=201)
async def upload_apk(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload an APK file and create a new analysis job."""
    try:
        analysis_id, sha256, file_size, apk_path = await validate_and_store_apk(file)
    except UploadValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create database record
    analysis = Analysis(
        id=analysis_id,
        sha256=sha256,
        original_filename=file.filename or "unknown.apk",
        file_size=file_size,
        status=AnalysisStatus.QUEUED,
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    # Submit background analysis job
    await job_service.submit(analysis_id)

    logger.info(
        "Analysis queued | analysis_id=%s | filename=%s",
        analysis_id,
        file.filename,
    )

    return AnalysisCreated(
        id=analysis.id,
        sha256=analysis.sha256,
        original_filename=analysis.original_filename,
        file_size=analysis.file_size,
        status=analysis.status.value,
        created_at=analysis.created_at,
    )


@router.get("", response_model=AnalysisListResponse)
async def list_analyses(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List all analyses, newest first."""
    # Count total
    count_result = await db.execute(select(func.count(Analysis.id)))
    total = count_result.scalar() or 0

    # Fetch page
    result = await db.execute(
        select(Analysis)
        .order_by(Analysis.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    analyses = result.scalars().all()

    items = [
        AnalysisSummary(
            id=a.id,
            sha256=a.sha256,
            original_filename=a.original_filename,
            file_size=a.file_size,
            status=a.status.value,
            created_at=a.created_at,
            risk_score=a.risk_score,
            risk_level=a.risk_level,
        )
        for a in analyses
    ]

    return AnalysisListResponse(items=items, total=total)


@router.get("/{analysis_id}", response_model=AnalysisStatusSchema)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the status and metadata of a specific analysis."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return AnalysisStatusSchema(
        id=analysis.id,
        sha256=analysis.sha256,
        original_filename=analysis.original_filename,
        file_size=analysis.file_size,
        status=analysis.status.value,
        created_at=analysis.created_at,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        error_message=analysis.error_message,
    )


@router.get("/{analysis_id}/results", response_model=AnalysisResults)
async def get_results(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the structured analysis findings and score breakdown."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    results = None
    if analysis.results_json:
        results = json.loads(analysis.results_json)

    return AnalysisResults(
        id=analysis.id,
        status=analysis.status.value,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        results=results,
    )


@router.get("/{analysis_id}/report", response_model=AnalysisReport)
async def get_report(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the AI-generated security assessment report."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    ai_report = None
    report_available = False
    if analysis.ai_report:
        ai_report = json.loads(analysis.ai_report)
        report_available = "error" not in ai_report

    return AnalysisReport(
        id=analysis.id,
        status=analysis.status.value,
        ai_report=ai_report,
        report_available=report_available,
    )


@router.delete("/{analysis_id}", status_code=204)
async def delete_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an analysis and clean up its workspace."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Clean up disk workspace
    cleanup_workspace(analysis_id)

    # Remove from database
    await db.delete(analysis)
    await db.commit()

    logger.info("Analysis deleted | analysis_id=%s", analysis_id)
