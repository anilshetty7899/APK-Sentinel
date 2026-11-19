"""HTTP boundary for the internal Android runtime analysis service."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import httpx

from app.config import settings


class DynamicServiceError(RuntimeError):
    pass


class DynamicAnalysisClient:
    def __init__(self) -> None:
        if not settings.DYNAMIC_ANALYSIS_BASE_URL or not settings.DYNAMIC_ANALYSIS_API_KEY:
            raise DynamicServiceError("Dynamic Analysis Service Unavailable: service URL or API key is not configured")
        self.base_url = settings.DYNAMIC_ANALYSIS_BASE_URL.rstrip("/")
        self.timeout = httpx.Timeout(settings.DYNAMIC_ANALYSIS_TIMEOUT, connect=15)

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = settings.DYNAMIC_ANALYSIS_API_KEY
        try:
            response = httpx.request(method, f"{self.base_url}{endpoint}", headers=headers, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            try:
                payload = response.json()
            except ValueError as exc:
                raise DynamicServiceError("Dynamic analysis service returned malformed JSON") from exc
            if isinstance(payload, dict) and payload.get("error"):
                raise DynamicServiceError("Dynamic analysis service could not complete the requested operation")
            return payload
        except httpx.TimeoutException as exc:
            raise DynamicServiceError("Dynamic analysis service timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise DynamicServiceError(f"Dynamic analysis service returned HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise DynamicServiceError("Dynamic Analysis Service Unavailable") from exc

    def upload_apk(self, path: Path) -> dict[str, Any]:
        with path.open("rb") as apk:
            return self._request("POST", "/api/v1/upload", files={"file": ("application.apk", apk, "application/vnd.android.package-archive")})

    def register_static_scan(self, sha256: str) -> dict[str, Any]:
        return self._request("POST", "/api/v1/scan", data={"hash": sha256, "scan_type": "apk"})

    def list_devices(self) -> Any:
        return self._request("GET", "/api/v1/dynamic/get_apps")

    def start_dynamic(self, scan_hash: str, device_id: str | None = None) -> dict[str, Any]:
        data = {"hash": scan_hash}
        if device_id:
            data["identifier"] = device_id
        return self._request("POST", "/api/v1/dynamic/start_analysis", data=data)

    def stop_dynamic(self, scan_hash: str, device_id: str | None = None) -> dict[str, Any]:
        data = {"hash": scan_hash}
        if device_id:
            data["identifier"] = device_id
        return self._request("POST", "/api/v1/dynamic/stop_analysis", data=data)

    def get_report(self, scan_hash: str) -> dict[str, Any]:
        return self._request("POST", "/api/v1/dynamic/report_json", data={"hash": scan_hash})

