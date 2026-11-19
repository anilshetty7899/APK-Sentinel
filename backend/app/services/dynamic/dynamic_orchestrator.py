"""Orchestrate the optional remote Android runtime analysis session."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import time
from app.services.dynamic.mobsf_client import DynamicAnalysisClient, DynamicServiceError
from app.services.dynamic.mobsf_normalizer import normalize_report


def run_dynamic_analysis(apk_path: Path, sha256: str, static_results: dict[str, Any], is_cancelled=lambda: False) -> list[dict[str, Any]]:
    client = DynamicAnalysisClient()
    uploaded = client.upload_apk(apk_path)
    service_hash = uploaded.get("hash") or uploaded.get("md5")
    if not isinstance(service_hash, str):
        raise DynamicServiceError("Dynamic analysis service did not return an APK identifier")
    client.register_static_scan(service_hash)
    devices = client.list_devices()
    device_list = devices.get("devices", []) if isinstance(devices, dict) else []
    online_devices = [
        device for device in device_list
        if isinstance(device, dict) and device.get("state") == "device"
        and isinstance(device.get("identifier"), str)
    ]
    if not devices or (isinstance(devices, dict) and devices.get("error")) or not online_devices:
        raise DynamicServiceError("No Android runtime device is available")
    from app.config import settings
    configured_device = settings.DYNAMIC_ANALYSIS_DEVICE_ID.strip()
    if configured_device:
        device = next(
            (item for item in online_devices if item["identifier"] == configured_device),
            None,
        )
        if device is None:
            raise DynamicServiceError("The configured Android runtime device is not connected")
    elif len(online_devices) == 1:
        device = online_devices[0]
    else:
        raise DynamicServiceError("Choose one Android runtime device before starting dynamic analysis")
    device_id = device["identifier"]
    client.start_dynamic(service_hash, device_id)
    # MobSF starts the app and runtime instrumentation. Keep the capture window
    # explicit/configurable; users may interact with a connected emulator too.
    try:
        deadline = time.monotonic() + max(1, min(900, settings.DYNAMIC_ANALYSIS_MAX_RUNTIME))
        while time.monotonic() < deadline:
            if is_cancelled():
                raise DynamicServiceError("Dynamic analysis cancelled")
            time.sleep(min(1, deadline - time.monotonic()))
    finally:
        client.stop_dynamic(service_hash, device_id)
    report = client.get_report(service_hash)
    if report.get("error") or not any(key in report for key in ("droidmon", "apimon", "tls_tests", "urls", "domains")):
        raise DynamicServiceError("Runtime analysis did not return a completed dynamic report")
    return normalize_report(report)
