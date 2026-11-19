# APK Sentinel

**AI-assisted Android APK security analysis platform.**

> Runtime analysis is optional and requires a separately provisioned, isolated Android analysis service and connected emulator/device. Without it, APK Sentinel performs static analysis only.

## Overview

APK Sentinel is a web-based platform that allows users to upload Android APK files for automated static security analysis. The system decompiles the APK inside an isolated Docker container, runs a battery of analyzers, computes a deterministic risk score, and generates an AI-powered security assessment report.

### Key Principles

1. **Isolated analysis** — static analysis uses the analyzer container; optional runtime analysis uses a separate Android runtime service
2. **Deterministic scoring** — The LLM never calculates or overrides the risk score
3. **Explainable results** — Every score point has a traceable rule, evidence, and explanation
4. **Evidence-based findings** — Findings are indicators, never definitive malware claims
5. **Isolated analysis** — Untrusted APKs are analyzed inside a sandboxed Docker container

## Architecture

```
Browser → Frontend (React/TypeScript/Vite)
              ↓
         FastAPI Backend
              ↓
         Upload / Quarantine → Analysis DB (SQLite)
              ↓
         Background Job (AnalysisJobService)
              ↓
         Isolated Docker Analyzer Container
              ├── APKTool 2.10.0 (decode/decompile)
              ├── JADX 1.5.5 (Java source decompilation)
              ├── Manifest Analyzer
              ├── Permission Analyzer + Correlation Engine
              ├── Component Analyzer
              ├── Suspicious API Analyzer
              ├── URL/IP Extractor
              ├── Secret Detector
              ├── Obfuscation Analyzer
              └── Certificate Analyzer
              ↓
         Raw Findings JSON (no score)
              ↓
         Deterministic Scoring Engine (backend; combined only after complete runtime coverage)
              ↓
         Groq LLM (report generation only)
              ↓
         Results Dashboard
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy, SQLite |
| Frontend | React, TypeScript, Vite, Tailwind CSS v3 |
| Analysis | APKTool 2.10.0, JADX 1.5.5, Python |
| AI | Groq API (llama-3.3-70b-versatile) |
| Isolation | Docker (non-root, no network, resource limits) |

## Installation

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- Python 3.12+ (for backend development)

### Quick Start

```bash
# Clone the repository
git clone <repo-url> && cd sentinel

# Copy environment file
cp backend/.env.example backend/.env
# Edit backend/.env and set GROQ_API_KEY

# Build the analyzer container
docker build -t apk-sentinel-analyzer ./analyzer

docker compose up -d mobsf

docker compose up --build backend frontend

# Start all services
docker compose up --build
```

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### Local Development (without Docker)

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite+aiosqlite:///./sentinel.db` |
| `GROQ_API_KEY` | Groq API key (required for AI reports) | — |
| `VIRUSTOTAL_LOOKUP_ENABLED` | Enable hash-only VirusTotal report lookup | `false` |
| `VIRUSTOTAL_API_KEY` | VirusTotal Community API key; required when lookup is enabled | — |
| `MAX_APK_SIZE_MB` | Maximum upload size in MB | `100` |
| `ANALYSIS_TIMEOUT_SECONDS` | Hard timeout for analyzer container | `900` |
| `CORS_ORIGINS` | Allowed CORS origins (JSON array) | `["http://localhost:5173"]` |

VirusTotal integration is optional and performs a hash lookup only. Set
`VIRUSTOTAL_LOOKUP_ENABLED=true` and provide `VIRUSTOTAL_API_KEY` in
`backend/.env` to enable it. APK Sentinel does not upload APK bytes to
VirusTotal; if no report exists or the lookup is unavailable, its own static
scan still runs. A hash lookup is externally visible to VirusTotal, so enable
it only for files you are permitted to query.

### Optional Dynamic Analysis

APK Sentinel can send an uploaded APK to a separately operated internal analysis service. That service must have a supported Android emulator or physical test device reachable by ADB, plus the runtime instrumentation components required by its supported version. APK Sentinel does not start an Android emulator inside Docker Compose: emulator acceleration, nested virtualization, ADB networking, and device isolation depend on the deployment host. Keep the service on a private network and do not publish its API or emulator/ADB ports to the public internet.

Compose starts the internal analysis service as the `mobsf` service. Its web/API UI is bound to `http://localhost:8001` (port 8000 is already APK Sentinel's backend), while APK Sentinel reaches it privately at `http://mobsf:8000`. The local ignored `backend/.env` holds `DYNAMIC_ANALYSIS_API_KEY` and `MOBSF_API_KEY`; use the same randomly generated key for both. The repository's `.env.example` is a template and does not contain a real key.

Configure these values in `backend/.env`:

| Variable | Purpose | Default |
|----------|---------|---------|
| `DYNAMIC_ANALYSIS_ENABLED` | Allow users to request runtime analysis | `false` |
| `DYNAMIC_ANALYSIS_BASE_URL` | Private base URL for the internal analysis service | empty |
| `DYNAMIC_ANALYSIS_API_KEY` | API key for that service; keep secret | empty |
| `DYNAMIC_ANALYSIS_TIMEOUT` | Maximum integration request time in seconds | `900` |
| `DYNAMIC_ANALYSIS_MAX_RUNTIME` | Runtime observation window in seconds | `120` |
| `DYNAMIC_ANALYSIS_MAX_CONCURRENT_JOBS` | Maximum simultaneous runtime sessions | `1` |
| `STATIC_SCORE_WEIGHT` | Static share of completed combined score | `0.75` |
| `DYNAMIC_SCORE_WEIGHT` | Runtime share of completed combined score | `0.25` |

Use the internal service's documented API key and REST API. Verify its API connectivity and Android device discovery before enabling the upload option. APK Sentinel uploads and registers the APK for its static prerequisite, checks Android device availability, starts and stops a runtime session, and normalizes supported report evidence. Actual emulator behavior must be validated against the selected service version and device; this repository's environment has not been verified end-to-end with an Android emulator. No runtime result means the original static score is retained and coverage is marked static-only. A combined score is produced only after a completed dynamic report.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyses` | Upload APK and create analysis (`enable_dynamic_analysis=true` multipart field is optional) |
| `GET` | `/api/analyses` | List all analyses (paginated) |
| `GET` | `/api/analyses/{id}` | Get analysis status/metadata |
| `GET` | `/api/analyses/{id}/results` | Get structured findings + score |
| `GET` | `/api/analyses/{id}/report` | Get AI security report |
| `DELETE` | `/api/analyses/{id}` | Delete analysis and cleanup |
| `GET` | `/api/health` | Health check |

## Scoring Methodology

The **Static Security Risk Score** (0-100) is computed by a deterministic engine:

| Category | Weight | Description |
|----------|--------|-------------|
| Permission Risk | 25% | Individual permissions + correlation rules |
| Code/API Risk | 35% | Security-sensitive API usage patterns |
| Component Exposure | 20% | Exported components and protection status |
| Indicators/Metadata | 20% | Secrets, network indicators, obfuscation |

### Risk Levels

| Range | Level |
|-------|-------|
| 0–20 | LOW |
| 21–40 | MODERATE |
| 41–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

Every score contribution includes: `rule_id`, `category`, `severity`, `points`, `evidence`, `explanation`.

When runtime analysis is requested and completes, unique normalized runtime findings use points CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3, INFO=0, capped at 100. The weighted score is `static × STATIC_SCORE_WEIGHT + dynamic × DYNAMIC_SCORE_WEIGHT`; the final score is the greater of that weighted score and the static score, so runtime observations cannot lower risk already established statically. The defaults are 0.75 and 0.25. This engineering weighting is not a calibrated probability. If runtime analysis is not requested, unavailable, or fails, the unchanged static-only score is retained; missing runtime evidence is never scored as zero.

## Threat Model & Security

### Primary Threat

The main threat is **malicious or malformed APK input**. Users upload untrusted Android application packages that could contain:

- Malformed archive structures designed to exploit decompilation tools
- Extremely large files intended to exhaust resources
- Path traversal filenames

### Container Isolation

The analyzer container is the primary security boundary:

| Control | Implementation |
|---------|---------------|
| Non-root execution | Container runs as `analyzer` user |
| No network | `network_mode=none` |
| No privileges | `privileged=false` |
| No Docker socket | Not mounted |
| No host filesystem | Controlled volume mounts only |
| Resource limits | CPU quota + memory limit (512MB) |
| Hard timeout | Container killed after 300s |
| Read-only input | APK mounted as read-only |
| Tmpfs for tools | APKTool/JADX temp dirs on tmpfs |
| Cleanup | Container + workspace removed after completion |

### What the Analyzer Can and Cannot Prove

| Can Detect | Cannot Determine |
|------------|-----------------|
| Dangerous permissions | User consent context |
| Exported components | Runtime behavior |
| Suspicious API patterns | Actual data exfiltration |
| Hardcoded secrets | Whether secrets are test/prod |
| Obfuscation indicators | Malicious intent |
| Network indicators | Active C2 communication |

### Separation of Detection and Explanation

The system deliberately separates:

1. **Deterministic detection/scoring** (backend engine) — objective, reproducible, auditable
2. **LLM-based explanation** (Groq) — human-readable interpretation of deterministic findings

The LLM never overrides scores or makes malware determinations. If the LLM fails, all static analysis results remain available.

## Limitations

- Runtime behavior is observed only when a separately configured Android environment is available; an observation window does not guarantee complete app coverage
- Cannot detect time-delayed or conditional malicious behavior
- Cannot verify if detected permissions are actually used at runtime
- Obfuscated code may limit decompilation quality
- Network indicators are extracted, not verified against threat intelligence
- Secret detection uses pattern matching, not confirmed credential validation
- AI report quality depends on LLM model capabilities and availability

## Future Extensibility

The analyzer architecture supports adding new modules:

- `YaraAnalyzer` — YARA rule matching
- `DynamicAnalyzer` — Runtime analysis via isolated Android emulator (separate pipeline)
- Threat intelligence integration for network indicators
- SBOM (Software Bill of Materials) generation
- Comparative analysis across APK versions

Dynamic analysis, when implemented, must use a completely separate isolated Android emulator/sandbox environment and would observe: runtime API calls, filesystem changes, network traffic, DNS queries, and process behavior.

## Testing

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

Tests use safe synthetic APK fixtures. **No real malware is used in testing.**

## License

[Your License Here]
# APK-Sentinel
