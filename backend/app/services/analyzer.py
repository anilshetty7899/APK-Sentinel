"""Analysis job service abstraction.

Provides an AnalysisJobService interface so the background-task
implementation (currently FastAPI BackgroundTasks) can later be replaced
by Redis + Celery/RQ without changing the API layer.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_factory
from app.models import Analysis, AnalysisStatus
from app.utils.logging import logger


class AnalysisJobService(ABC):
    """Abstract interface for submitting analysis jobs.

    Implementations can use in-process background tasks, Celery, RQ, etc.
    """

    @abstractmethod
    async def submit(self, analysis_id: str) -> None:
        """Submit an analysis job for processing."""
        ...


class BackgroundTaskJobService(AnalysisJobService):
    """MVP implementation using asyncio tasks (in-process).

    Runs the analysis pipeline in a background thread to avoid blocking
    the FastAPI event loop. The Docker SDK is synchronous, so we use
    asyncio.to_thread for all blocking operations.
    """

    async def submit(self, analysis_id: str) -> None:
        """Fire-and-forget: launch analysis in a background asyncio task."""
        asyncio.create_task(self._run_analysis(analysis_id))

    async def _run_analysis(self, analysis_id: str) -> None:
        """Execute the full analysis pipeline for a given analysis ID."""
        async with async_session_factory() as session:
            try:
                # Mark as RUNNING
                analysis = await session.get(Analysis, analysis_id)
                if not analysis:
                    logger.error("Analysis not found | analysis_id=%s", analysis_id)
                    return

                analysis.status = AnalysisStatus.RUNNING
                analysis.started_at = datetime.now(timezone.utc)
                await session.commit()

                logger.info("Analysis started | analysis_id=%s", analysis_id)

                # Run Docker analyzer in thread (blocking Docker SDK calls)
                workspace = settings.analysis_path / analysis_id
                results = await asyncio.to_thread(
                    self._run_docker_analyzer, analysis_id, workspace
                )

                if results is None:
                    raise RuntimeError("Analyzer container produced no results")

                # Run scoring engine on results
                from app.services.scoring import ScoringEngine
                scoring_engine = ScoringEngine()
                scored_results = scoring_engine.calculate_score(results)

                # Store results
                analysis.results_json = json.dumps(scored_results)
                analysis.risk_score = scored_results.get("score", {}).get("total", 0)
                analysis.risk_level = scored_results.get("score", {}).get("level", "LOW")

                # Generate AI report (non-blocking, graceful degradation)
                try:
                    from app.services.groq_report import generate_report
                    ai_report = await generate_report(scored_results)
                    analysis.ai_report = json.dumps(ai_report) if ai_report else None
                except Exception as e:
                    logger.warning(
                        "AI report generation failed (static results preserved) | "
                        "analysis_id=%s | error=%s",
                        analysis_id, str(e),
                    )
                    analysis.ai_report = json.dumps({
                        "error": "AI report generation failed",
                        "detail": str(e),
                        "note": "Static analysis results and deterministic score are still available."
                    })

                analysis.status = AnalysisStatus.COMPLETED
                analysis.completed_at = datetime.now(timezone.utc)
                await session.commit()

                logger.info(
                    "Analysis completed | analysis_id=%s | score=%.1f | level=%s",
                    analysis_id,
                    analysis.risk_score or 0,
                    analysis.risk_level or "UNKNOWN",
                )

            except Exception as e:
                logger.error(
                    "Analysis failed | analysis_id=%s | error=%s",
                    analysis_id, str(e),
                )
                try:
                    analysis = await session.get(Analysis, analysis_id)
                    if analysis:
                        analysis.status = AnalysisStatus.FAILED
                        analysis.error_message = str(e)
                        analysis.completed_at = datetime.now(timezone.utc)
                        await session.commit()
                except Exception:
                    logger.error("Failed to update analysis status to FAILED")

    def _run_docker_analyzer(
        self, analysis_id: str, workspace: Path
    ) -> Optional[dict]:
        """Run the analyzer Docker container (blocking, runs in thread).

        The container is configured with strict security constraints:
        - Non-root user inside container
        - network_mode=none (no network access)
        - CPU and memory limits
        - No Docker socket access
        - No privileged mode
        - Read-only APK input, controlled writable output
        - Hard timeout
        - Cleanup after completion
        """
        import docker
        from docker.errors import ContainerError, ImageNotFound, APIError

        client = docker.from_env()

        # Bind sources are resolved by the Docker daemon, which may run
        # outside the backend container. ANALYSIS_HOST_DIR points at the same
        # shared directory from the daemon's point of view.
        daemon_workspace = settings.analysis_host_path / analysis_id
        daemon_input_dir = daemon_workspace / "input"
        daemon_output_dir = daemon_workspace / "output"
        input_dir = workspace / "input"
        output_dir = workspace / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        container = None
        try:
            container = client.containers.run(
                image=settings.ANALYZER_IMAGE,
                # The image ENTRYPOINT decodes the APK and runs the analyzer.
                command=[],
                volumes={
                    str(daemon_input_dir): {
                        "bind": "/analysis/input",
                        "mode": "ro",  # Read-only mount for untrusted APK
                    },
                    str(daemon_output_dir): {
                        "bind": "/analysis/output",
                        "mode": "rw",  # Writable output directory
                    },
                },
                # Security constraints
                network_mode="none",
                mem_limit=settings.ANALYZER_MEM_LIMIT,
                cpu_period=settings.ANALYZER_CPU_PERIOD,
                cpu_quota=settings.ANALYZER_CPU_QUOTA,
                privileged=False,
                read_only=True,
                environment={"HOME": "/tmp", "ANALYSIS_ID": analysis_id},
                tmpfs={
                    "/tmp": "size=256m",  # APKTool/JADX temp dirs
                },
                # No Docker socket, no host PID/IPC
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                pids_limit=128,
                detach=True,
                remove=False,  # We remove manually after reading results
            )

            # Wait for container with timeout
            result = container.wait(timeout=settings.ANALYSIS_TIMEOUT_SECONDS)
            exit_code = result.get("StatusCode", -1)

            # Capture logs for debugging
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            if exit_code != 0:
                logger.error(
                    "Analyzer container failed | analysis_id=%s | exit_code=%d | logs=%s",
                    analysis_id, exit_code, logs[:2000],
                )
                raise RuntimeError(
                    f"Analyzer container exited with code {exit_code}. "
                    f"Recent analyzer output: {logs[-3000:]}"
                )

            logger.info("Analyzer container completed | analysis_id=%s", analysis_id)

            # Read results
            results_file = output_dir / "findings" / "analysis_results.json"
            if results_file.exists():
                with open(results_file, "r") as f:
                    return json.load(f)
            else:
                raise RuntimeError(
                    "Analyzer did not produce results file. "
                    f"Recent analyzer output: {logs[-3000:]}"
                )

        except ImageNotFound:
            raise RuntimeError(
                f"Analyzer image '{settings.ANALYZER_IMAGE}' not found. "
                "Build it with: docker build -t apk-sentinel-analyzer ./analyzer"
            )
        except APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
        finally:
            # Clean up container
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass


# Singleton for the MVP
job_service = BackgroundTaskJobService()
