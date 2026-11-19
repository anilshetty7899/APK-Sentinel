# APK-Sentinel — Dynamic Analysis Integration
## Master Implementation Prompt for ChatGPT / AI Coding Agent

---

# 1. PROJECT CONTEXT

You are working on an existing cybersecurity project called **APK-Sentinel**.

GitHub Repository:
https://github.com/BharathHonnappa/APK-Sentinel

Your task is to extend APK-Sentinel by implementing a complete, production-oriented Android Dynamic Analysis module and integrating it with the existing static analysis pipeline.

This is NOT a request to build a separate Android security scanner.

The objective is to make APK-Sentinel a unified Android application security assessment platform that combines:

1. Static Analysis (existing implementation).
2. Dynamic Analysis (new implementation).
3. Unified Vulnerability Detection.
4. Combined Risk Scoring.
5. AI-assisted Security Reporting.
6. A unified dashboard showing the application's overall security posture.

The existing application must remain functional throughout the implementation.

**Do not unnecessarily rewrite, replace, or remove existing functionality.**

---

# 2. MOST IMPORTANT ARCHITECTURAL REQUIREMENT

## MobSF must remain an internal dependency.

We are integrating the Mobile Security Framework (MobSF) as the underlying dynamic analysis engine.

Repository:
https://github.com/MobSF/Mobile-Security-Framework-MobSF

MobSF is responsible for providing runtime analysis capabilities.

However, APK-Sentinel must remain the actual product presented to users.

### Strict branding requirements

The following names must NEVER appear in the user-facing application:

- MobSF
- Mobile Security Framework
- MobSF-powered
- MobSF Analysis
- MobSF Score
- MobSF Report

This restriction applies to:

- Frontend UI.
- Dashboard.
- Analysis progress messages.
- Vulnerability descriptions.
- AI-generated explanations.
- PDF reports.
- Exported JSON reports.
- User-facing API responses.
- Error messages.
- Notifications.

Instead, use APK-Sentinel's own terminology.

Examples:

| Internal implementation | User-facing terminology |
|---|---|
| MobSF dynamic analysis | Dynamic Security Analysis |
| MobSF report | Runtime Security Findings |
| MobSF API | Internal Analysis Service |
| MobSF scan status | Dynamic Analysis Status |
| MobSF findings | Runtime Findings |
| MobSF score | Dynamic Risk Score |
| MobSF integration failure | Dynamic Analysis Service Unavailable |

The AI report generator must never expose internal engine names when explaining findings.

**Important:** This is a user-interface and product-branding requirement, not permission to remove required open-source copyright notices, licenses, legal attribution, or internal technical documentation. Keep operational logs and configuration understandable to developers.

Do not falsely claim that APK-Sentinel independently implements instrumentation that is actually supplied by an underlying dependency.

---

# 3. FIRST TASK: UNDERSTAND THE EXISTING CODEBASE

Before writing or modifying any code, inspect the complete repository.

Repository:
https://github.com/BharathHonnappa/APK-Sentinel

Do not assume the architecture described in this document is still identical to the latest code.

Verify everything against the actual implementation.

Inspect:

### Backend

- FastAPI application.
- API routes.
- APK upload mechanism.
- Background task processing.
- Static analysis orchestration.
- APKTool integration.
- JADX integration.
- Manifest analyzer.
- Permission analyzer.
- Component analyzer.
- Code/API analyzers.
- Indicator detection.
- Scoring engine.
- Database models.
- LLM integration.
- Report generation.
- Error handling.

### Frontend

- Framework and project structure.
- APK upload page.
- Analysis progress UI.
- Results dashboard.
- Vulnerability cards.
- Risk score visualization.
- Report generation.
- API communication.
- Existing design system.

### Important existing file

Inspect:

`backend/app/services/scoring.py`

Understand:

- Existing category weights.
- Individual finding rules.
- Severity points.
- Normalization.
- Deduplication.
- Final score calculation.
- Risk classification.

Do not replace the existing scoring logic without understanding its behavior.

Also inspect the README and update it after implementation.

### Deliverable before coding

Provide a concise architecture summary containing:

1. Existing static analysis workflow.
2. Existing scoring formula.
3. Existing API structure.
4. Existing database structure.
5. Existing frontend result structure.
6. Exact files that need modifications.
7. New files that need creation.
8. Any infrastructure requirements.

Then proceed with implementation. Do not stop after producing an architecture proposal.

---

# 4. DYNAMIC ANALYSIS ENGINE

Use MobSF as the primary underlying dynamic analysis engine.

Official repository:

https://github.com/MobSF/Mobile-Security-Framework-MobSF

Official documentation:

https://mobsf.github.io/docs/

GitHub:

https://github.com/MobSF/Mobile-Security-Framework-MobSF

Do not recreate its existing capabilities unnecessarily.

Use its REST API and integrate it with APK-Sentinel's FastAPI backend.

### Expected capabilities

The dynamic analysis implementation should collect and process:

#### A. Network Analysis

- HTTP and HTTPS requests.
- Unencrypted HTTP communication.
- Sensitive information transmitted over insecure connections.
- Suspicious external endpoints.
- Network traffic observations.
- TLS configuration weaknesses.
- Certificate validation issues where detectable.

#### B. Runtime API Monitoring

- Runtime API calls.
- Sensitive Android API usage.
- Dynamic code loading.
- Reflection-related behavior.
- Suspicious execution patterns.
- Runtime interactions with sensitive resources.

#### C. Storage Analysis

- Sensitive information stored locally.
- Insecure file permissions.
- Sensitive application data.
- Potentially exposed databases.
- Insecure SharedPreferences.
- Sensitive information exposed in logs.

#### D. Privacy Analysis

- Clipboard access.
- Sensitive data handling.
- Potential information leakage.
- Sensitive data exposed through application behavior.

#### E. Application Behavior

- Application startup behavior.
- Activity execution.
- Runtime interactions.
- Logcat observations.
- Screenshots.
- Dynamic application behavior.

Only report findings that are supported by actual collected evidence.

Do not invent vulnerabilities simply because a particular API was observed.

---

# 5. INFRASTRUCTURE AND ENVIRONMENT

Dynamic analysis requires an Android runtime environment.

Design the integration around:

- MobSF running as an isolated service.
- Android emulator or supported physical Android device.
- ADB connectivity.
- Frida instrumentation.
- APK-Sentinel FastAPI backend.
- Secure communication between services.

### Recommended architecture

APK-Sentinel backend
    |
    | Upload and analysis orchestration
    |
    +---- Static Analysis Engine
    |
    +---- Dynamic Analysis Adapter
                |
                | REST API
                |
                +---- Internal Analysis Service
                           |
                           +---- Android Emulator
                           |
                           +---- ADB
                           |
                           +---- Frida
                           |
                           +---- Runtime Data Collection

Both analysis branches should eventually feed into:

Finding Normalization
        |
Finding Correlation and Deduplication
        |
Combined Scoring Engine
        |
AI Report Generator
        |
APK-Sentinel Dashboard

### Infrastructure requirements

1. Provide Docker Compose configuration for the dynamic analysis service where appropriate.
2. Document Android emulator requirements.
3. Document ADB configuration.
4. Document Frida requirements and compatibility.
5. Provide environment variables for service configuration.
6. Avoid hardcoding API keys, tokens, passwords or service URLs.
7. Provide health checks.
8. Implement connection timeout and retry handling.
9. Handle unavailable emulators gracefully.
10. Make the dynamic service configurable rather than hardcoding a particular machine's environment.

Do not assume Docker can run a complete Android emulator without additional configuration.

Investigate the host's virtualization, networking and device requirements before selecting the final deployment strategy.

---

# 6. BACKEND IMPLEMENTATION

Create a modular dynamic analysis subsystem.

Suggested structure:

backend/
└── app/
    ├── api/
    │   └── routes/
    │       └── dynamic.py
    │
    ├── services/
    │   ├── scoring.py
    │   │
    │   └── dynamic/
    │       ├── __init__.py
    │       ├── mobsf_client.py
    │       ├── dynamic_orchestrator.py
    │       ├── mobsf_normalizer.py
    │       ├── dynamic_scoring.py
    │       ├── finding_correlator.py
    │       └── device_manager.py
    │
    ├── models/
    │   └── dynamic_analysis.py
    │
    └── schemas/
        └── dynamic.py

This is a proposed structure. Adapt it to the existing project conventions instead of blindly creating duplicate modules.

## 6.1 Internal service client

Implement `mobsf_client.py`.

Responsibilities:

- Connect to the internal analysis service.
- Authenticate using a securely stored API key.
- Upload APKs.
- Register static scans when required by the runtime workflow.
- Check available dynamic devices.
- Retrieve available applications.
- Start dynamic analysis.
- Check analysis status.
- Stop analysis.
- Retrieve JSON reports.
- Handle service errors.
- Apply request timeouts.
- Handle malformed responses.
- Provide structured exceptions.

Keep all internal service communication inside this client.

Do not scatter HTTP requests to the underlying service throughout the application.

## 6.2 Dynamic orchestrator

Implement `dynamic_orchestrator.py`.

Responsibilities:

1. Receive an APK-Sentinel analysis job.
2. Verify the APK and its hash.
3. Check dynamic analysis availability.
4. Submit the APK to the internal service.
5. Complete any required static prerequisite for runtime testing.
6. Verify emulator/device availability.
7. Install and execute the application.
8. Start runtime monitoring.
9. Collect runtime findings.
10. Stop the analysis session safely.
11. Retrieve the final report.
12. Pass findings to the normalizer.
13. Save the results.
14. Trigger combined scoring.

The orchestrator must handle:

- Timeouts.
- Device disconnection.
- Installation failures.
- Application crashes.
- Instrumentation failures.
- Analysis interruption.
- Partial results.
- Service unavailability.
- Job cancellation.

Do not mark a failed or incomplete dynamic analysis as successfully completed.

## 6.3 Finding normalizer

Implement `mobsf_normalizer.py`.

Convert the underlying analysis report into APK-Sentinel's existing standardized finding format.

Do not expose raw third-party report structures directly to the frontend.

Suggested finding structure:

{
    "id": "unique-finding-id",
    "source": "dynamic",
    "category": "network",
    "title": "Sensitive Data Transmitted Over HTTP",
    "severity": "HIGH",
    "confidence": "HIGH",
    "description": "Description supported by runtime evidence",
    "evidence": {
        "endpoint": "http://example.test/api",
        "method": "POST",
        "observed_behavior": "Sensitive data transmitted without encryption"
    },
    "recommendation": "Use HTTPS and appropriate transport security controls",
    "cwe": null,
    "references": [],
    "first_observed": null
}

This is a target schema, not an assumption about the existing database schema.

Inspect the existing finding structure and reuse compatible fields wherever possible.

### Normalization requirements

- Preserve original evidence.
- Normalize severity.
- Normalize confidence.
- Deduplicate equivalent findings.
- Avoid duplicate reports from repeated runtime observations.
- Retain useful evidence locations.
- Redact credentials and personal data.
- Keep source information internally for debugging and provenance.

Do not automatically assign HIGH severity to every suspicious runtime event.

---

# 7. COMBINED SCORING ENGINE

This is one of the most important requirements.

APK-Sentinel must calculate one final application risk score using both static and dynamic analysis.

Do not use the underlying engine's score as the final APK-Sentinel score.

Do not allow the LLM to calculate or modify security scores.

The scoring must remain deterministic.

## 7.1 Existing static scoring

Preserve the current static scoring implementation.

Previously inspected implementation uses:

| Static category | Weight |
|---|---:|
| Permissions | 30% |
| Code/API risk | 40% |
| Component exposure | 15% |
| Indicators and metadata | 15% |

Verify these weights against the current source code before implementing.

If they have changed, follow the actual code.

## 7.2 Proposed combined scoring

Use the following initial weighting:

Static Risk: 75%

Dynamic Risk: 25%

Formula:

Final Risk Score = (Static Score × 0.75) + (Dynamic Score × 0.25)

Where both subscores are normalized between 0 and 100.

These weights are initial engineering defaults, not experimentally validated security probabilities.

Keep them configurable.

Do not silently modify existing static category weights.

## 7.3 Dynamic severity points

Initial proposed values:

| Severity | Points |
|---|---:|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO | 0 |

Dynamic score:

Dynamic Risk = min(100, sum of unique finding points)

Implement proper deduplication and evidence-based confidence handling.

Do not count every repeated API invocation as a new vulnerability.

## 7.4 Confidence and finding correlation

Implement confidence-aware handling.

Examples:

- Confirmed sensitive data transmitted over HTTP: strong runtime evidence.
- Suspicious API call without evidence of exploitation: lower confidence.
- Static detection of an insecure endpoint, confirmed by runtime traffic: correlated finding.
- Same vulnerability discovered by both engines: one vulnerability with combined evidence, not two unrelated vulnerabilities.

Preserve the individual evidence sources internally.

## 7.5 Missing dynamic analysis

This is critical.

If dynamic analysis is:

- Not requested.
- Not configured.
- Unavailable.
- Failed.
- Incomplete.

Do not treat the dynamic score as zero.

Do not automatically calculate:

Final = Static × 0.75

when no valid dynamic result exists.

Instead:

- Retain the existing static-only score.
- Display the analysis coverage.
- Clearly identify dynamic analysis as unavailable, incomplete or not requested.
- Mark the result as static-only.
- Calculate the combined score only when the dynamic analysis result meets the required completion criteria.

Do not give applications an artificially better score because dynamic testing failed.

## 7.6 Score interpretation

Inspect the existing risk classification thresholds.

Preserve them unless there is a justified reason to revise them.

Ensure that a higher score consistently means higher security risk.

Document the score methodology.

---

# 8. AUTOMATED APPLICATION INTERACTION

Consider integrating DroidBot:

https://github.com/honeynet/droidbot

DroidBot can automatically interact with Android applications.

Its purpose is to improve runtime coverage by triggering different application screens and workflows.

It should complement the primary runtime analysis engine, not replace it.

Potential capabilities:

- Automatic UI exploration.
- Screen transitions.
- Button interactions.
- Input field interactions.
- Navigation testing.
- Application state exploration.

Implement this as an optional module.

Do not make DroidBot a mandatory dependency for the first working integration.

### Important testing limitations

- Authentication may require test credentials.
- Some screens require specific user actions.
- Server-side functionality may require backend access.
- Dynamic code paths may not execute without proper input.
- UI automation does not guarantee full code coverage.

Show runtime coverage limitations in the report.

Never claim that an application is completely secure merely because no dynamic vulnerabilities were detected.

---

# 9. FRONTEND IMPLEMENTATION

Integrate dynamic analysis into the existing APK-Sentinel interface.

Do not redesign the entire application.

Follow the existing design system, layout, typography and components.

## 9.1 Upload interface

Add an option:

[ ] Enable Dynamic Analysis

If selected, the analysis pipeline should include runtime analysis.

If not selected, preserve the existing static-only workflow.

Clearly explain that dynamic analysis requires an available Android runtime environment.

## 9.2 Analysis progress

Show individual analysis stages.

Example:

1. APK uploaded.
2. Static analysis running.
3. Static analysis completed.
4. Preparing runtime environment.
5. Installing application.
6. Launching application.
7. Monitoring runtime behavior.
8. Collecting network activity.
9. Collecting runtime findings.
10. Correlating findings.
11. Calculating final risk score.
12. Generating security report.

Progress must reflect actual backend job status.

Do not use fake progress percentages or pretend an analysis has completed.

## 9.3 Results dashboard

Add a dedicated Dynamic Analysis section.

Recommended layout:

Application Security Overview

Final Risk Score: XX/100

Static Analysis: XX/100

Dynamic Analysis: XX/100

Analysis Coverage: Completed / Partial / Not Available

Then display:

### Static Findings

Existing findings and functionality.

### Dynamic Findings

Runtime findings with:

- Vulnerability title.
- Severity.
- Confidence.
- Description.
- Runtime evidence.
- Affected endpoint or component.
- Impact.
- Remediation.

### Correlated Findings

Show findings that were identified by static and dynamic analysis together.

Highlight the additional evidence.

### Overall Security Posture

Display the final score and risk classification.

Do not display internal engine branding anywhere.

---

# 10. AI REPORT GENERATION

Extend the existing Groq LLM report generator.

The AI should receive:

1. Static findings.
2. Dynamic findings.
3. Correlated findings.
4. Evidence.
5. Severity.
6. Confidence.
7. Final deterministic score.
8. Analysis coverage.
9. Testing limitations.

The AI should produce:

- Executive summary.
- Overall risk assessment.
- Critical vulnerabilities.
- High-risk vulnerabilities.
- Static analysis summary.
- Dynamic analysis summary.
- Correlated vulnerabilities.
- Exploitation impact.
- Remediation recommendations.
- Security improvement priorities.
- Testing limitations.

### AI restrictions

The LLM must:

- Never invent vulnerabilities.
- Never invent runtime observations.
- Never invent endpoints or credentials.
- Never change the deterministic risk score.
- Never upgrade severity without supporting evidence.
- Never claim an untested attack was successful.
- Never describe unobserved application behavior as confirmed.
- Never expose internal engine branding.
- Never expose API keys, passwords, tokens or sensitive captured data.

The LLM should explain findings, not act as the source of truth for vulnerability detection.

---

# 11. DATABASE AND API DESIGN

Inspect the current database before adding models.

Persist:

- Analysis ID.
- APK hash.
- Static analysis status.
- Dynamic analysis status.
- Static findings.
- Dynamic findings.
- Correlated findings.
- Static score.
- Dynamic score.
- Combined score.
- Analysis timestamps.
- Runtime coverage.
- Error information.
- Report references.

Use database migrations if the existing project uses a migration framework.

Do not store unnecessary raw traffic or sensitive user information.

Implement retention and cleanup for temporary APKs, emulator snapshots and captured data.

### Suggested API endpoints

Adapt these to the existing route naming conventions.

POST /api/analysis/{analysis_id}/dynamic/start

GET /api/analysis/{analysis_id}/dynamic/status

GET /api/analysis/{analysis_id}/dynamic/findings

GET /api/analysis/{analysis_id}/combined-report

POST /api/analysis/{analysis_id}/dynamic/cancel

These endpoints should return APK-Sentinel-native response schemas.

Do not expose internal engine endpoints or API credentials to the browser.

---

# 12. SECURITY REQUIREMENTS

Because APK-Sentinel itself is a security testing platform, its dynamic analysis infrastructure must also be secured.

Implement:

- Isolated emulator execution.
- APK hash verification.
- File type and APK validation.
- Secure temporary storage.
- Restricted network access.
- API authentication between services.
- No hardcoded secrets.
- No public ADB exposure.
- No unrestricted container privileges.
- Resource limits.
- Execution timeouts.
- Cleanup after analysis.
- Concurrent execution controls.
- Safe report parsing.
- Redaction of sensitive evidence.

Treat uploaded APKs as untrusted input.

Prevent APKs from accessing the host filesystem or other analysis jobs.

Use disposable emulator snapshots and restore the environment after testing.

Do not execute unknown APKs on the developer's personal Android device.

### Network isolation

Allow only the network access necessary for the analysis.

Where possible:

- Use a dedicated virtual network.
- Restrict outbound connections.
- Monitor traffic.
- Avoid access to internal infrastructure.
- Prevent access to cloud metadata endpoints.
- Provide controlled access to test application backends.

Do not accidentally expose emulator services or analysis APIs to the public internet.

---

# 13. TESTING REQUIREMENTS

Do not consider the implementation complete merely because the API returns HTTP 200.

Perform actual end-to-end tests.

Use deliberately vulnerable Android applications in an isolated lab.

Suggested test applications:

- DIVA (Damn Insecure and Vulnerable App).
- InsecureBankv2.
- OWASP MSTG UnCrackable Apps.
- A custom test APK with known insecure HTTP communication and insecure local storage.

Repository:

https://github.com/payatu/diva-android

### Test cases

1. Static-only APK analysis.
2. Static plus dynamic APK analysis.
3. APK upload to the internal analysis service.
4. Device discovery.
5. Application installation.
6. Application execution.
7. Runtime API monitoring.
8. HTTP traffic detection.
9. TLS-related observations.
10. Sensitive local storage detection.
11. Runtime report retrieval.
12. Finding normalization.
13. Finding deduplication.
14. Static/dynamic correlation.
15. Combined score calculation.
16. Analysis timeout.
17. Emulator unavailable.
18. Dynamic analysis failure.
19. Partial analysis.
20. AI report generation.
21. PDF report generation.
22. Branding leakage checks.

### Scoring tests

Write unit tests covering:

- Static score unchanged for static-only analysis.
- Dynamic score calculation.
- Combined score calculation.
- Severity point mapping.
- Confidence handling.
- Duplicate finding suppression.
- Cross-engine finding correlation.
- Missing dynamic results.
- Failed dynamic results.
- Partial dynamic results.
- Score boundaries between 0 and 100.

### Branding tests

Search user-facing source files, API responses, frontend text, AI prompts and generated report templates for internal engine names.

Ensure they are not exposed.

Do not remove required legal attribution or internal developer references.

---

# 14. CONFIGURATION

Provide an `.env.example` containing the necessary configuration.

Suggested variables:

DYNAMIC_ANALYSIS_ENABLED=true

DYNAMIC_ANALYSIS_BASE_URL=http://internal-analysis-service:8000

DYNAMIC_ANALYSIS_API_KEY=

DYNAMIC_ANALYSIS_TIMEOUT=900

DYNAMIC_ANALYSIS_MAX_CONCURRENT_JOBS=1

ANDROID_ADB_HOST=

ANDROID_ADB_PORT=

STATIC_SCORE_WEIGHT=0.75

DYNAMIC_SCORE_WEIGHT=0.25

DYNAMIC_ANALYSIS_MAX_RUNTIME=900

Adjust the variables to the actual MobSF API configuration and deployment architecture.

Do not assume the example hostname or port is correct without verifying the actual deployment.

Never commit real secrets.

---

# 15. IMPLEMENTATION ORDER

Implement the project in the following order.

## Phase 1: Codebase inspection

- Inspect existing backend.
- Inspect existing frontend.
- Inspect scoring engine.
- Understand database.
- Document existing architecture.
- Identify integration points.

## Phase 2: Infrastructure

- Set up the internal analysis service.
- Configure Android emulator.
- Configure ADB.
- Verify connectivity.
- Verify API authentication.
- Verify dynamic analysis works independently.

## Phase 3: Backend integration

- Implement internal service client.
- Implement dynamic orchestrator.
- Implement report normalizer.
- Implement dynamic finding storage.
- Implement API endpoints.
- Implement status handling.
- Implement cleanup.

## Phase 4: Scoring integration

- Implement dynamic scoring.
- Implement correlation.
- Implement deduplication.
- Extend existing scoring engine.
- Preserve static-only behavior.
- Add unit tests.

## Phase 5: Frontend integration

- Add dynamic analysis option.
- Add progress tracking.
- Add dynamic findings section.
- Add combined score.
- Add analysis coverage.
- Preserve existing UI functionality.

## Phase 6: AI reporting

- Extend existing AI prompt.
- Include both analysis types.
- Include evidence and limitations.
- Enforce deterministic scoring.
- Remove internal engine names from user-facing content.

## Phase 7: Testing

- Test with deliberately vulnerable APKs.
- Verify real runtime findings.
- Verify combined score.
- Verify static-only workflow.
- Verify error handling.
- Verify branding.
- Verify report generation.

## Phase 8: Documentation

Update:

- README.md.
- Architecture documentation.
- Installation instructions.
- Docker Compose documentation.
- Environment variables.
- Dynamic analysis setup.
- Emulator setup.
- API documentation.
- Scoring methodology.
- Troubleshooting guide.
- Known limitations.

---

# 16. DEVELOPMENT RULES

These rules are mandatory.

1. Inspect before modifying.
2. Do not blindly trust the architecture in this document; verify the repository.
3. Preserve existing static analysis functionality.
4. Preserve the current frontend design.
5. Do not replace the existing scoring engine.
6. Do not hardcode secrets.
7. Do not create duplicate functionality unnecessarily.
8. Do not use placeholder findings in production code.
9. Do not generate fake analysis progress.
10. Do not mark incomplete scans as completed.
11. Do not treat missing dynamic analysis as a zero score.
12. Do not let the LLM determine the final score.
13. Do not expose internal analysis engine branding to users.
14. Keep the integration modular.
15. Use asynchronous/background processing for long-running scans.
16. Add meaningful error handling and logging.
17. Add automated tests.
18. Use the existing project's coding conventions.
19. Keep the implementation maintainable.
20. Do not remove existing features to make integration easier.

If a proposed feature cannot be implemented reliably, explain the limitation and implement the best supported alternative.

Do not claim a feature is working unless it has actually been tested.

---

# 17. DEFINITION OF DONE

The integration is complete only when all the following conditions are met:

- [ ] APK-Sentinel can upload an APK.
- [ ] Existing static analysis works unchanged.
- [ ] Users can enable dynamic analysis.
- [ ] The backend can communicate with the internal analysis service.
- [ ] An Android emulator can be discovered.
- [ ] APKs can be installed and executed.
- [ ] Runtime behavior is monitored.
- [ ] Actual runtime findings are retrieved.
- [ ] Dynamic findings are normalized.
- [ ] Duplicate findings are handled.
- [ ] Static and dynamic findings can be correlated.
- [ ] Dynamic risk score is calculated.
- [ ] Combined risk score is calculated deterministically.
- [ ] Static-only scans remain supported.
- [ ] Failed and partial scans are represented correctly.
- [ ] The frontend displays static and dynamic results.
- [ ] The final report contains both analysis types.
- [ ] The LLM cannot modify the score.
- [ ] No internal engine name appears in user-facing content.
- [ ] Required open-source licensing notices are preserved.
- [ ] Security isolation and cleanup are implemented.
- [ ] Automated tests pass.
- [ ] End-to-end testing with vulnerable APKs succeeds.
- [ ] Documentation is updated.

---

# 18. FINAL EXPECTED RESULT

The finished APK-Sentinel should work as follows:

A user uploads an Android APK.

APK-Sentinel performs its existing static analysis.

If dynamic analysis is enabled, APK-Sentinel submits the APK to its internal runtime analysis service.

The Android application is installed and executed in an isolated emulator.

Runtime behavior, network communication, API activity, storage exposure and other supported security observations are collected.

The backend normalizes the runtime findings and correlates them with static findings.

The existing scoring engine is extended to calculate a deterministic combined application risk score.

The AI generates a comprehensive report explaining:

- What was discovered statically.
- What was observed during execution.
- Which vulnerabilities were confirmed by both methods.
- The actual security impact.
- Recommended remediation.
- Testing limitations.
- Final application risk score.

The user sees only **APK-Sentinel**.

The final product must feel like one cohesive Android application security assessment platform, not two different security tools stitched together.

---

# 19. INSTRUCTIONS TO THE IMPLEMENTING AI

You are not being asked to simply explain how to implement this project.

You are being asked to actually implement it in the available repository/workspace.

Start by inspecting the codebase.

Then produce the implementation plan and execute it phase by phase.

Modify the actual backend, frontend, configuration, database and documentation as necessary.

Run tests after each major implementation stage.

If you encounter an environment limitation, distinguish between:

- Code implemented.
- Code tested.
- Infrastructure configured.
- Functionality verified end-to-end.

Do not falsely claim completion.

At the end, provide:

1. Architecture changes.
2. New files created.
3. Existing files modified.
4. Dependencies added.
5. Environment variables required.
6. Infrastructure setup instructions.
7. Commands to start the complete application.
8. Tests executed and their results.
9. Remaining limitations.
10. A clear confirmation of whether real Android dynamic analysis was successfully verified.

**Your final objective: Deliver a working APK-Sentinel application with integrated static and dynamic Android security analysis and one reliable, evidence-based final risk score.**