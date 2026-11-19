"""Analysis job service abstraction.

Provides an AnalysisJobService interface so the background-task
implementation (currently FastAPI BackgroundTasks) can later be replaced
by Redis + Celery/RQ without changing the API layer.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_factory
from app.models import Analysis, AnalysisStatus
from app.services.progress import read_progress, write_progress as _write_progress
from app.utils.logging import logger


class AnalysisJobService(ABC):
    """Abstract interface for submitting analysis jobs.

    Implementations can use in-process background tasks, Celery, RQ, etc.
    """

    @abstractmethod
    async def submit(self, analysis_id: str) -> None:
        """Submit an analysis job for processing."""
        ...


class AnalysisCancelled(Exception):
    """Raised when a user cancels an in-flight analysis."""


class BackgroundTaskJobService(AnalysisJobService):
    """MVP implementation using asyncio tasks (in-process).

    Runs the analysis pipeline in a background thread to avoid blocking
    the FastAPI event loop. The Docker SDK is synchronous, so we use
    asyncio.to_thread for all blocking operations.
    """

    def __init__(self) -> None:
        self._state_lock = threading.Lock()
        self._cancel_requested: set[str] = set()
        self._active_containers: dict[str, str] = {}
        self._dynamic_semaphore = asyncio.Semaphore(max(1, settings.DYNAMIC_ANALYSIS_MAX_CONCURRENT_JOBS))

    def request_cancel(self, analysis_id: str) -> None:
        """Request cancellation and stop the active analyzer container, if any."""
        with self._state_lock:
            self._cancel_requested.add(analysis_id)
            container_id = self._active_containers.get(analysis_id)

        if container_id:
            client = None
            try:
                import docker

                client = docker.from_env(timeout=15)
                client.containers.get(container_id).kill()
            except Exception as exc:
                logger.warning(
                    "Could not immediately stop analyzer container | analysis_id=%s | error=%s",
                    analysis_id,
                    str(exc),
                )
            finally:
                if client:
                    client.close()

    def _is_cancel_requested(self, analysis_id: str) -> bool:
        with self._state_lock:
            return analysis_id in self._cancel_requested

    def _clear_cancel_request(self, analysis_id: str) -> None:
        with self._state_lock:
            self._cancel_requested.discard(analysis_id)

    def _register_container(self, analysis_id: str, container_id: str) -> bool:
        with self._state_lock:
            self._active_containers[analysis_id] = container_id
            return analysis_id in self._cancel_requested

    def _unregister_container(self, analysis_id: str) -> None:
        with self._state_lock:
            self._active_containers.pop(analysis_id, None)

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

                if self._is_cancel_requested(analysis_id):
                    analysis.status = AnalysisStatus.CANCELLED
                    analysis.error_message = "Scan cancelled by user"
                    analysis.completed_at = datetime.now(timezone.utc)
                    await session.commit()
                    _write_progress(settings.analysis_path / analysis_id, 0, "Cancelled by user")
                    self._clear_cancel_request(analysis_id)
                    return

                analysis.status = AnalysisStatus.RUNNING
                analysis.started_at = datetime.now(timezone.utc)
                await session.commit()
                _write_progress(
                    settings.analysis_path / analysis_id,
                    0,
                    "Checking VirusTotal for this SHA-256",
                )

                logger.info("Analysis started | analysis_id=%s", analysis_id)

                workspace = settings.analysis_path / analysis_id
                from app.services.virustotal import build_user_guidance, lookup_hash

                reputation = await lookup_hash(analysis.sha256)
                if self._is_cancel_requested(analysis_id):
                    raise AnalysisCancelled("Scan cancelled by user")

                # Run Docker analyzer in thread (blocking Docker SDK calls)
                _write_progress(workspace, 1, "Starting isolated analyzer")
                results = await asyncio.to_thread(
                    self._run_docker_analyzer, analysis_id, workspace
                )

                if results is None:
                    raise RuntimeError("Analyzer container produced no results")
                if self._is_cancel_requested(analysis_id):
                    raise AnalysisCancelled("Scan cancelled by user")

                # Run scoring engine on results
                _write_progress(workspace, 97, "Calculating risk score")
                from app.services.scoring import ScoringEngine
                scoring_engine = ScoringEngine()
                scored_results = scoring_engine.calculate_score(results)
                if analysis.dynamic_requested:
                    analysis.dynamic_status = "RUNNING"
                    await session.commit()
                    _write_progress(workspace, 97, "Running dynamic security analysis")
                    try:
                        from app.services.dynamic.dynamic_orchestrator import run_dynamic_analysis
                        from app.services.dynamic.finding_correlator import correlate_findings
                        async with self._dynamic_semaphore:
                            dynamic_findings = await asyncio.wait_for(
                                asyncio.to_thread(
                                    run_dynamic_analysis,
                                    workspace / "input" / "application.apk",
                                    analysis.sha256,
                                    scored_results,
                                    lambda: self._is_cancel_requested(analysis_id),
                                ),
                                timeout=settings.DYNAMIC_ANALYSIS_TIMEOUT,
                            )
                        correlated_findings, correlated = correlate_findings(scored_results, dynamic_findings)
                        from app.services.dynamic.dynamic_scoring import add_dynamic_score
                        scored_results = add_dynamic_score(scored_results, correlated_findings, correlated)
                        analysis.dynamic_status = "COMPLETED"
                        analysis.dynamic_error = None
                    except asyncio.CancelledError:
                        raise
                    except Exception as dynamic_error:
                        if self._is_cancel_requested(analysis_id):
                            raise AnalysisCancelled("Scan cancelled by user") from dynamic_error
                        # Preserve the verified static result; missing or failed
                        # runtime evidence must never become a zero dynamic score.
                        analysis.dynamic_status = "FAILED"
                        analysis.dynamic_error = str(dynamic_error)[:1000]
                        scored_results["dynamic_findings"] = []
                        scored_results["analysis_coverage"] = {
                            "static": "COMPLETED", "dynamic": "FAILED", "overall": "STATIC_ONLY"
                        }
                        logger.warning(
                            "Dynamic analysis unavailable; retaining static-only score | analysis_id=%s | error=%s",
                            analysis_id, str(dynamic_error),
                        )
                scored_results["virustotal"] = reputation
                scored_results["user_guidance"] = build_user_guidance(
                    scored_results, reputation
                )

                # Store results
                analysis.results_json = json.dumps(scored_results)
                analysis.risk_score = scored_results.get("score", {}).get("total", 0)
                analysis.risk_level = scored_results.get("score", {}).get("level", "LOW")

                # Generate AI report (non-blocking, graceful degradation)
                try:
                    _write_progress(workspace, 98, "Generating analysis report")
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

                if self._is_cancel_requested(analysis_id):
                    raise AnalysisCancelled("Scan cancelled by user")
                analysis.status = AnalysisStatus.COMPLETED
                analysis.completed_at = datetime.now(timezone.utc)
                await session.commit()
                _write_progress(workspace, 100, "Analysis complete")
                self._clear_cancel_request(analysis_id)

                logger.info(
                    "Analysis completed | analysis_id=%s | score=%.1f | level=%s",
                    analysis_id,
                    analysis.risk_score or 0,
                    analysis.risk_level or "UNKNOWN",
                )

            except Exception as e:
                if isinstance(e, AnalysisCancelled) or self._is_cancel_requested(analysis_id):
                    logger.info("Analysis cancelled | analysis_id=%s", analysis_id)
                else:
                    logger.error(
                        "Analysis failed | analysis_id=%s | error=%s",
                        analysis_id, str(e),
                    )
                try:
                    analysis = await session.get(Analysis, analysis_id)
                    if analysis:
                        cancelled = (
                            isinstance(e, AnalysisCancelled)
                            or self._is_cancel_requested(analysis_id)
                            or analysis.status == AnalysisStatus.CANCELLED
                        )
                        analysis.status = (
                            AnalysisStatus.CANCELLED if cancelled else AnalysisStatus.FAILED
                        )
                        if analysis.dynamic_requested and analysis.dynamic_status in {"QUEUED", "RUNNING"}:
                            analysis.dynamic_status = "CANCELLED" if cancelled else "FAILED"
                            analysis.dynamic_error = (
                                "Dynamic analysis was cancelled."
                                if cancelled
                                else "Dynamic analysis did not complete."
                            )
                        analysis.error_message = (
                            "Scan cancelled by user" if cancelled else str(e)
                        )
                        analysis.completed_at = datetime.now(timezone.utc)
                        await session.commit()
                        _write_progress(
                            settings.analysis_path / analysis_id,
                            int((read_progress(settings.analysis_path / analysis_id) or {}).get("percent", 0)),
                            "Cancelled by user" if cancelled else "Analysis failed",
                        )
                        self._clear_cancel_request(analysis_id)
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

        # Docker SDK's default HTTP read timeout is 60 seconds. A container
        # wait request can exceed that for large APKs, so use short polling
        # calls and a separate overall analysis deadline below.
        client = docker.from_env(timeout=15)

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
            _write_progress(workspace, 2, "Preparing APK decode")
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
                environment={
                    "HOME": "/tmp",
                    # JADX derives its config path from the JVM system
                    # property, which otherwise points at /home/analyzer
                    # (read-only in this container).
                    "JAVA_TOOL_OPTIONS": "-Duser.home=/tmp",
                    "ANALYSIS_ID": analysis_id,
                },
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
            if self._register_container(analysis_id, container.id):
                container.kill()

            # Poll instead of using container.wait(): the Docker SDK wait
            # request can time out at its HTTP layer before the analyzer's
            # configured timeout, and it gives us no opportunity to publish
            # live progress to the API.
            deadline = time.monotonic() + settings.ANALYSIS_TIMEOUT_SECONDS
            while True:
                if self._is_cancel_requested(analysis_id):
                    try:
                        container.kill()
                    except Exception:
                        pass
                    raise AnalysisCancelled("Scan cancelled by user")
                container.reload()
                if container.status == "exited":
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Analyzer exceeded {settings.ANALYSIS_TIMEOUT_SECONDS} seconds"
                    )
                _update_progress_from_logs(workspace)
                time.sleep(1)

            exit_code = container.attrs.get("State", {}).get("ExitCode", -1)

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
            _write_progress(workspace, 96, "Collecting scan findings")

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
            self._unregister_container(analysis_id)
            # Clean up container
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass


def _update_progress_from_logs(workspace: Path) -> None:
    """Translate APKTool, JADX, and analyzer phase logs into user progress."""
    output_dir = workspace / "output"
    jadx_log = output_dir / "logs" / "jadx.log"
    analysis_log = output_dir / "logs" / "analysis.log"
    apktool_log = output_dir / "logs" / "apktool.log"

    if analysis_log.exists():
        try:
            lines = analysis_log.read_text(errors="replace").splitlines()
            latest = next(
                (line for line in reversed(lines) if line.startswith("[Analysis]")),
                "",
            )
        except OSError:
            latest = ""
        phases = [
            ("Computing APK metadata", 66, "Reading APK metadata"),
            ("Parsing AndroidManifest.xml", 68, "Reading XML manifest and resources"),
            ("Analyzing permissions", 72, "Analyzing permissions"),
            ("Analyzing components", 76, "Inspecting app components"),
            ("Scanning for suspicious APIs", 80, "Scanning code and API usage"),
            ("Extracting network indicators", 84, "Extracting network indicators"),
            ("Detecting potential secrets", 88, "Checking for embedded secrets"),
            ("Analyzing obfuscation", 91, "Analyzing obfuscation"),
            ("Analyzing certificate", 94, "Inspecting signing certificate"),
            ("Results written", 96, "Finishing scan results"),
            ("Pipeline complete", 96, "Finishing scan results"),
        ]
        for marker, percent, stage in phases:
            if marker in latest:
                _write_progress(workspace, percent, stage)
                return
        _write_progress(workspace, 65, "Starting static analysis checks")
        return

    if jadx_log.exists():
        try:
            with jadx_log.open("rb") as log_file:
                log_file.seek(0, 2)
                log_size = log_file.tell()
                log_file.seek(max(0, log_size - 65536))
                log_text = log_file.read().decode("utf-8", errors="replace")
            log_text = log_text.replace("\r", "\n")
        except OSError:
            log_text = ""
        matches = re.findall(r"progress:\s*\d+\s+of\s+\d+\s+\((\d+)%\)", log_text)
        if matches:
            jadx_percent = min(100, int(matches[-1]))
            overall_percent = 5 + round(jadx_percent * 0.60)
            stage = f"Decompiling APK ({jadx_percent}% of code)"
            _write_progress(workspace, overall_percent, stage)
        else:
            _write_progress(workspace, 5, "Decompiling APK")
        return

    if apktool_log.exists():
        _write_progress(workspace, 3, "Decoding APK manifest and bytecode")


# Singleton for the MVP
job_service = BackgroundTaskJobService()
