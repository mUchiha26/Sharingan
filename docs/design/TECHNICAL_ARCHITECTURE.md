# Phase 1: Foundation Architecture (Weeks 1-2)

## 1.1 Core Design Principles

```text
┌─────────────────────────────────────────┐
│  SHARINGAN MVP ARCHITECTURE PRINCIPLES  │
├─────────────────────────────────────────┤
│ ✓ Human-in-the-loop at every decision   │
│ ✓ Defense-in-depth for the tool itself  │
│ ✓ Auditability & non-repudiation        │
│ ✓ Modular plugin architecture           │
│ ✓ Async-first for scalability           │
│ ✓ Secure-by-default configuration       │
└─────────────────────────────────────────┘
```

```text
sharingan/
│
├── 📁 src/
│   ├── 📁 core/
│   │   ├── __init__.py
│   │   ├── orchestrator.py          # State machine workflow engine
│   │   ├── plugin_manager.py        # Dynamic module loading with sandboxing
│   │   ├── config_loader.py         # Pydantic-based config validation
│   │   └── security_context.py      # RBAC, audit logging, secrets handling
│   │
│   ├── 📁 modules/                   # Plugin-style security modules
│   │   ├── 📁 recon/
│   │   │   ├── base.py              # Abstract base class for all modules
│   │   │   ├── nmap_wrapper.py
│   │   │   ├── amass_wrapper.py
│   │   │   └── ...
│   │   ├── 📁 web/
│   │   ├── 📁 auth/
│   │   └── 📁 post_exploit/
│   │
│   ├── 📁 ai/
│   │   ├── __init__.py
│   │   ├── base_provider.py         # Abstract AI interface
│   │   ├── ollama_client.py         # Local model handler
│   │   ├── openai_client.py         # Cloud model handler
│   │   ├── prompt_templates/        # Versioned, auditable prompts
│   │   │   ├── recon_analysis.j2
│   │   │   ├── attack_suggestion.j2
│   │   │   └── report_synthesis.j2
│   │   └── guardrails.py            # Output validation & safety checks
│   │
│   ├── 📁 data/
│   │   ├── models.py                # Pydantic schemas for all data
│   │   ├── repositories.py          # Abstract data access layer
│   │   └── serializers.py           # JSON/CSV/PDF output handlers
│   │
│   └── 📁 utils/
│       ├── logging_config.py        # Structured JSON logging
│       ├── rate_limiter.py          # Prevent tool abuse
│       ├── subprocess_manager.py    # Safe external tool execution
│       └── validators.py            # Input sanitization & validation
│
├── 📁 config/
│   ├── base.yaml                    # Default secure settings
│   ├── development.yaml             # Dev overrides (no prod secrets)
│   ├── production.yaml.example      # Template for deployment
│   └── policies/
│       ├── module_allowlist.json    # Which tools can be executed
│       ├── ai_usage_policy.json     # AI query limits & content filters
│       └── engagement_rules.json    # Scope boundaries for engagements
│
├── 📁 tests/
│   ├── 📁 unit/
│   ├── 📁 integration/
│   ├── 📁 security/                 # SAST/DAST tests for Sharingan itself
│   └── conftest.py
│
├── 📁 docs/
│   ├── architecture/
│   ├── contributing/
│   ├── security/
│   └── user-guides/
│
├── 📁 scripts/
│   ├── setup_dev.sh                 # One-time dev environment setup
│   ├── run_scan.py                  # CLI entry point with argparse
│   └── audit_export.py              # Compliance report generator
│
├── pyproject.toml                   # Modern Python packaging (Poetry)
├── Dockerfile                       # Multi-stage, non-root container
├── docker-compose.yml               # Local dev with Redis/Postgres
├── .github/workflows/               # CI/CD: test, security scan, build
├── SECURITY.md                      # Responsible disclosure policy
├── LICENSE                          # Clear usage terms (AGPL recommended)
└── README.md                        # Updated with MVP status
```

## 1.3 Technology Stack Recommendations

| Component               | Python Library                   | Purpose                                                 | MVP Ready? |
| ----------------------- | -------------------------------- | ------------------------------------------------------- | ---------- |
| Config & Validation     | pydantic-settings, pyyaml        | Type-safe config loading                                | ✅         |
| Logging & Audit         | structlog, python-json-logger    | Structured, queryable audit trails                      | ✅         |
| External Tool Execution | python-nmap, subprocess (stdlib) | Safe, parsed scanning output                            | ✅         |
| Local AI/LLM            | ollama, httpx                    | Local Qwen inference with timeout and fallback handling | ✅         |
| Data Models             | pydantic                         | Input/output validation and schema consistency          | ✅         |
| Reporting               | weasyprint, jinja2               | HTML-to-PDF generation with reusable templates          | ✅         |
| Task Queue (v0.3+)      | celery, redis                    | Async parallel scanning and workload isolation          | ❌ Later   |
| MITRE Integration       | attackcti                        | TAXII/STIX client for ATT&CK data sync and cache        | ❌ v0.3    |
| Testing                 | pytest, hypothesis, bandit       | Unit, property-based, and security checks               | ✅         |
| CLI Framework           | argparse (MVP), click (later)    | Command routing and operator workflow                   | ✅         |

# Phase 2: Security-by-Design Implementation

## 2.1 Critical Security Controls for the Tool Itself

The MVP enforces explicit engagement scope before any module runs, logs every operator action to immutable JSON lines, and defaults to deny when configuration is missing or invalid. Role-oriented permissions are kept minimal at first (recon/report) and expanded only when higher-risk features are introduced. Secrets are read from environment variables and never printed in logs, prompts, or reports.

## 2.2 Secure External Tool Execution

External tools are executed through a strict wrapper that enforces an allowlist of binaries, argument sanitization, process timeout, and non-zero exit code handling. No shell interpolation is allowed; commands are executed as argument lists to reduce injection risk. Raw outputs are normalized into structured models before downstream AI analysis and reporting.

## 2.3 AI Safety & Guardrails

AI outputs are treated as recommendations, not executable actions. Prompts include explicit scope and rules-of-engagement context, while responses are validated for format, target scope, and unsafe content before display. If validation fails, the system returns a safe fallback response and requests human review.

# Phase 3: Core Logic & Workflow Engine

## 3.1 Orchestrator Design Pattern

The orchestrator follows a state-driven flow: request intake, scope validation, module execution, AI analysis, human approval checkpoint, and reporting. Each stage returns typed results and explicit status codes so failures remain isolated and diagnosable. This pattern keeps modules independent while preserving a predictable end-to-end workflow.

## 3.2 MITRE ATT&CK Integration Strategy

MITRE ATT&CK is integrated through a local cache periodically refreshed from TAXII/STIX sources, avoiding runtime dependence on external availability. Findings map to ATT&CK techniques during analysis, and reports include both technique IDs and plain-language rationale. The mapping layer remains optional in early MVP runs and becomes mandatory in v0.3.

# Phase 4: Reliability & Scalability Patterns

## 4.1 Async Task Queue Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   CLI/API   │────▶│  Redis Queue │────▶│  Workers    │
│   Request   │     │  (Celery)    │     │  (Pool)     │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
              ┌─────────────────────────────────┼─────────────────────────┐
              ▼                                 ▼                         ▼
    ┌─────────────────┐            ┌─────────────────┐        ┌─────────────────┐
    │ Recon Workers   │            │ AI Analysis     │        │ Report Gen      │
    │ (CPU-bound)     │            │ (I/O-bound)     │        │ (I/O-bound)     │
    │ - Rate limited  │            │ - Retry logic   │        │ - Template engine│
    │ - Timeout enforced│          │ - Fallback models│       │ - PDF/HTML/JSON │
    └─────────────────┘            └─────────────────┘        └─────────────────┘
```

## 4.2 Resilience Patterns to Implement

| Pattern            | Implementation                               | Benefit                                       |
| ------------------ | -------------------------------------------- | --------------------------------------------- |
| Circuit Breaker    | For AI API calls & external tools            | Prevent cascade failures ijsrm.net            |
| Retry with Backoff | Exponential backoff for transient errors     | Handle rate limits, network issues            |
| Bulkheads          | Separate thread pools for recon/AI/reporting | Isolate failures, prevent resource starvation |
| Health Checks      | /health endpoint checking deps, disk, memory | Enable orchestration (K8s, systemd)           |
| Graceful Shutdown  | Signal handling to finish in-flight tasks    | Prevent data loss during updates              |

## 4.3 Configuration Management (Secure & Flexible)

Configuration is centralized in YAML with Pydantic validation at startup to fail fast on invalid settings. Environment-specific overrides are supported without code changes, while sensitive values are injected through environment variables. Policy files (module allowlist, AI usage, engagement rules) remain version-controlled and auditable.

# Phase 5: Testing & Quality Assurance

## 5.1 Test Pyramid for Security Tools

```text
        ┌─────────────────┐
        │  E2E Scenarios  │  ← 10%: Full engagement simulations
        ├─────────────────┤
        │ Integration     │  ← 20%: Module + AI + DB interactions
        ├─────────────────┤
        │ Unit Tests      │  ← 70%: Pure functions, validators, parsers
        └─────────────────┘
```

## 5.2 Security Testing the Tool Itself

Security testing includes static analysis (Bandit), dependency audits, and regression tests for scope enforcement, subprocess safety, and prompt guardrails. Integration tests verify that blocked targets never execute and that malformed AI responses are safely handled. CI must fail on critical vulnerabilities or policy bypass regressions.

# Phase 6: Deployment & Operations

## 6.1 Docker Hardening Checklist

Use multi-stage builds, minimal base images, and a non-root runtime user. Install only required system packages, pin dependency versions, and remove build-time caches from final images. Add health checks, read-only root filesystem where possible, and explicit resource limits for safer runtime behavior.

## 6.2 Operational Security Controls

| Control            | Implementation                            | Purpose                                        |
| ------------------ | ----------------------------------------- | ---------------------------------------------- |
| Scope Enforcement  | Pre-execution target validation           | Legal compliance, prevent accidental attacks   |
| Audit Logging      | Immutable JSON logs to stdout             | Forensics, compliance, debugging               |
| Rate Limiting      | Token bucket per operator/target          | Avoid detection, respect target infrastructure |
| Secrets Management | Environment variables + Vault integration | Prevent credential leakage in logs/code        |
| Update Mechanism   | Signed releases + SHA256 verification     | Prevent supply chain attacks                   |

# Phase 7: Version Roadmap

| Version | Focus                                       | Features                                                                                                                           | Learning Outcome                                        |
| ------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| v0.1    | Core Recon & AI Advisory                    | Safe nmap wrapper, local Qwen/Ollama analysis, JSON and PDF reporting, immutable audit logging, basic pytest coverage.             | Learn the smallest secure end-to-end workflow.          |
| v0.2    | Plugin System & Async Workflow              | Module base class, dynamic loading, ffuf/nuclei/httpx modules, asyncio execution, approval checkpoint, config-driven allowlisting. | Learn async Python, plugin design, and CLI ergonomics.  |
| v0.3    | Knowledge Integration & Compliance Mapping  | attackcti integration, local MITRE cache, ATT&CK and NIST mapping, HTML/PDF views, refresh flag, integration tests.                | Learn TAXII/STIX, compliance mapping, and templating.   |
| v1.0    | Production-Ready Workflow                   | Multi-target scoping, human review UI, pause/resume, deduplication, CSV/JSON/PDF/MITRE Navigator exports, CI security checks.      | Learn how to make the tool reliable for real use.       |
| v1.5    | Defensive Feedback & Monitoring Integration | Wazuh/Suricata ingestion, detection mapping, alert validation loop, gap reports, vector-based correlation.                         | Learn SIEM integration and detection engineering.       |
| v2.0    | AI-Augmented Validation Engine              | Multi-agent pipeline, safe validation checks, plugin marketplace, role-based access, stateful deployment.                          | Learn how to scale the platform without losing control. |
