# VACE — Vulnerability Assessment Consolidation Engine

**VACE** takes the raw output of multiple security scanners and turns it into a single, prioritized, de-duplicated list of findings — with a calm, notebook-style interface instead of the usual red-flashing dashboard.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Design System](#design-system)
5. [Quick Start](#quick-start)
6. [Project Structure](#project-structure)
7. [Key Features Deep-Dive](#key-features-deep-dive)
8. [API Endpoints](#api-endpoints)
9. [Future Roadmap](#future-roadmap)
10. [Contributing & License](#contributing--license)

---

## Project Overview

Security teams running Nessus for network scanning and SonarQube for static analysis end up with two separate streams of findings that never talk to each other — the same weak TLS cipher reported on every node behind a load balancer, the same CVE flagged twice with slightly different metadata, dozens of low-severity items burying the three that actually matter. Triaging that by hand doesn't scale.

VACE ingests findings from both tools into one normalized schema, runs them through a three-tier deduplication engine that collapses repeat reports into a single canonical finding with a confidence score, and surfaces the result through a filterable findings list, a stats dashboard, and one-click PDF technical reports. Credentials for each scanner are stored encrypted at rest, never re-displayed once saved.

The interface is deliberately understated. Vulnerability data is already stressful to look at; VACE's design system swaps the usual dark-mode/red-alert aesthetic for a warm paper background, hand-lettered fonts, and severity indicators that live entirely on outlines and text — never on filled, alarming blocks of color. The goal is a tool a security analyst can stare at for eight hours without it adding to the noise.

## Features

- **Multi-tool ingestion** — normalizes findings from Nessus (network/host) and SonarQube (static code analysis) into one consistent schema; ZAP is already modeled as a source (`ToolSource.ZAP`) with a connector planned next (see [Roadmap](#future-roadmap))
- **Three-tier deduplication with confidence scoring** — exact CVE+location matches, cross-host CVE matches (load-balanced infrastructure), and CVE-less matches on shared CWE + title-keyword overlap, each tagged with a confidence score rather than silently merged
- **PDF technical report generation** — on-demand reports for a whole scan or an arbitrary set of findings, with executive summary, per-finding evidence/remediation write-ups, and an affected-systems appendix
- **Encrypted credential storage** — Nessus and SonarQube API keys are Fernet-encrypted at rest and never returned by the API once saved, including immediately after a save
- **Hand-drawn design system** — warm paper background, Kalam/Patrick Hand typography, wobble-filtered SVG icons, and severity colors that only ever appear as outlines or text
- **Full REST API** — scan import, findings querying/filtering/pagination, stats, credentials, and report generation, all under `/api/v1`
- **Database migrations (Alembic)** — schema changes tracked and applied via versioned migrations rather than ad hoc DDL

## Tech Stack

| Layer | Technologies |
|---|---|
| **Backend** | FastAPI · SQLAlchemy 2.0 · PostgreSQL · Alembic · Pydantic v2 · reportlab (PDF generation) · `cryptography` (Fernet) |
| **Frontend** | React 19 · Vite · Tailwind CSS v4 · React Router · Axios |
| **Infrastructure** | Docker Compose (PostgreSQL + Redis) |
| **Design** | Kalam + Patrick Hand (Google Fonts) · hand-drawn inline SVG icon set |

> Redis is provisioned in `docker-compose.yml` for future caching/async task-queue use (scan imports currently run as FastAPI background tasks, not a Redis-backed queue).

## Design System

VACE's frontend follows a "warm notebook" design language — the opposite of the dark, high-contrast dashboards typical of security tooling.

- **Color palette**: a warm paper background (`#ece8df`), an off-white surface for cards (`#fbf9f3`), and an ink-toned text scale (`#2b2925` → `#a39d8f`) for everything else
- **Severity accents**: critical/high/medium/low/resolved/info each get a distinct color, but — by design rule — **only as an outline, border, or text color, never as a fill**. A page full of findings never turns into a wall of red and orange blocks
- **Typography**: [Kalam](https://fonts.google.com/specimen/Kalam) for headings and display text, [Patrick Hand](https://fonts.google.com/specimen/Patrick+Hand) for body and UI copy — both hand-lettered, neither a joke font
- **Shape language**: cards, buttons, and badges use slightly irregular, asymmetric corner radii instead of uniform `border-radius`, and icons are single-stroke SVGs run through an `feTurbulence`/`feDisplacementMap` filter for a hand-drawn wobble

The underlying principle: **severity should be legible, not alarming.** You should be able to tell a CRITICAL finding from a LOW one at a glance without the page itself raising your heart rate.

## Quick Start

### Prerequisites

- [Docker](https://www.docker.com/) + Docker Compose
- Python 3.11+
- Node.js 18+

### 1. Clone and install

```bash
git clone https://github.com/SageTerry/Zimatik-VA-System.git
cd Zimatik-VA-System

# Backend
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### 2. Configure environment

Copy `.env.example` to `backend/.env` and fill in a `CREDENTIAL_ENCRYPTION_KEY` (generate one with the command below) plus any scanner defaults you want pre-filled:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Start services

From the **project root**, bring up PostgreSQL (and Redis):

```bash
docker-compose up -d postgres redis
```

From **`backend/`** (venv activated):

```bash
alembic upgrade head              # apply the schema
python -m app.seed_data           # optional: load ~20 realistic demo findings
uvicorn app.main:app --reload --port 8001
```

From **`frontend/`**:

```bash
npm run dev
```

### 4. Access

- **Frontend:** [http://localhost:5173](http://localhost:5173)
- **API docs (Swagger):** [http://localhost:8001/docs](http://localhost:8001/docs)

## Project Structure

```
Zimatik VA System/
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI routers (findings, credentials)
│   │   ├── models/               # SQLAlchemy models (Finding, Scan, CredentialStore)
│   │   ├── services/
│   │   │   ├── deduplication.py     # Three-tier dedup engine
│   │   │   ├── report_generator.py  # reportlab PDF generation
│   │   │   ├── crypto.py            # Fernet encrypt/decrypt for credentials
│   │   │   ├── nessus_client.py     # Nessus API client + normalization
│   │   │   └── sonarqube_client.py  # SonarQube API client + normalization
│   │   ├── config.py             # Pydantic settings, sourced from .env
│   │   ├── database.py           # Engine/session setup
│   │   ├── main.py               # FastAPI app entrypoint
│   │   └── seed_data.py          # Demo data seeding script
│   ├── alembic/                  # Migration environment + versions/
│   ├── tests/                    # pytest suite (deduplication engine coverage)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/client.js         # Axios client, one function per endpoint
│   │   ├── components/           # Button, Badge, Card, StatCard, ProgressBar,
│   │   │                         # Dashboard, FindingsList, FindingDetail, SettingsPage
│   │   ├── lib/
│   │   │   ├── constants.js      # Severity/status → badge variant mappings
│   │   │   ├── icons.jsx         # Hand-drawn wobble-filtered SVG icon set
│   │   │   └── download.js       # File-download helpers for report PDFs
│   │   ├── index.css             # Tailwind entrypoint + design tokens
│   │   └── App.jsx               # Router + nav shell
│   └── tailwind.config.js        # Design system tokens (colors, spacing, fonts)
├── docs/                         # Project documentation
└── docker-compose.yml            # PostgreSQL + Redis for local development
```

## Key Features Deep-Dive

### Deduplication

`DeduplicationEngine` (`backend/app/services/deduplication.py`) resolves each newly-imported finding against everything already on file, trying three tiers from most to least certain and stopping at the first match:

| Tier | Match Criteria | Confidence | Example |
|---|---|---|---|
| **1** | Same CVE **and** exact location (host+port, code file+line, or URL+parameter) | 0.95 | Nessus and ZAP both report CVE-2021-12345 on the same host/port |
| **2** | Same CVE, **different host**, matching port/service | 0.70 | The same vulnerable library version deployed to every node behind a load balancer |
| **3** | No CVE — same CWE, matching port/service, **and** overlapping title keyword | 0.65 | The same weak-TLS-cipher misconfiguration mirrored across load-balanced hosts, caught without a CVE to key off |

A finding that doesn't clear any tier is kept as its own canonical record; one that matches is flagged `is_duplicate`, linked to its `canonical_id`, and stamped with the tier's `dedup_confidence` — nothing is silently merged below a scored threshold.

### PDF Technical Reports

`ReportGenerator` (`backend/app/services/report_generator.py`, built on `reportlab`) renders a client-ready PDF from any scan or arbitrary set of findings: an executive summary with severity counts, a full findings table, a detailed write-up (description, evidence, CVSS, remediation) for every Critical/High finding, and an appendix of affected systems. Triggered from the Dashboard, Findings list, or a single Finding's detail view via `POST /api/v1/reports/technical`.

### Credential Management

Nessus and SonarQube credentials are stored one row per tool (`CredentialStore`), with `api_key`/`api_secret` Fernet-encrypted before they touch the database. The API never echoes a stored key or secret back — not even immediately after saving — so the frontend only ever knows a tool is "configured," never what the credential actually is. A "Test Connection" endpoint validates whatever is currently stored without accepting new credentials in the request.

### Design System

See [Design System](#design-system) above — implemented as Tailwind v4 theme tokens (`frontend/tailwind.config.js`), a shared icon library with a hand-drawn SVG filter (`frontend/src/lib/icons.jsx`), and a small set of reusable components (`Button`, `Badge`, `Card`, `StatCard`, `ProgressBar`) that keep severity color usage constrained to outlines and text everywhere it's used.

## API Endpoints

All routes are prefixed with `/api/v1` (full interactive docs at `/docs`).

| Method | Path | Description |
|---|---|---|
| `POST` | `/scans/import` | Trigger a background import from one or more tools (`{"scan_name", "tools": ["NESSUS", "SONARQUBE"]}`) |
| `GET` | `/findings` | List findings, filterable by `severity`, `tool`, `host`, `scan_id`; paginated, sorted Critical-first |
| `GET` | `/findings/{id}` | Full detail for a single finding |
| `GET` | `/scans` | List all scans with per-severity finding counts |
| `GET` | `/stats` | Dashboard summary: totals by severity, by tool, and affected host count |
| `POST` | `/reports/technical` | Generate a PDF technical report for a `scan_id` or a list of `finding_ids` |
| `GET` | `/credentials/{tool}` | Whether a tool has stored credentials (base URL only — never the key) |
| `POST` | `/credentials` | Save/update credentials for a tool (`NESSUS` or `SONARQUBE`) |
| `DELETE` | `/credentials/{tool}` | Clear stored credentials for a tool |
| `POST` | `/credentials/{tool}/test` | Test the currently-stored connection for a tool |

Example: fetching only unresolved Critical findings from Nessus, newest first:

```bash
curl "http://localhost:8001/api/v1/findings?severity=CRITICAL&tool=NESSUS&page=1&page_size=25"
```

## Future Roadmap

- **Mobile application security scanning** — MobSF and/or Snyk integration for a third finding source alongside Nessus/SonarQube
- **OWASP ZAP connector** — wire up the already-modeled `ZAP` tool source with an importer, the way Nessus/SonarQube work today
- **Executive report generation** — a non-technical HTML/PDF summary report for stakeholders, distinct from the existing technical report
- **Remediation roadmap tracking** — timelines, ownership, and SLA tracking layered on top of `remediation_status`
- **Webhook/automation support** — scheduled or event-driven scanner imports instead of manually triggering `POST /scans/import`
- **Multi-user support with role-based access** — the credential store and API are currently single-tenant by design; this would add auth, users, and per-role permissions

## Contributing & License

This is a portfolio project built to demonstrate full-stack security tooling design — data modeling for messy multi-source vulnerability data, a deduplication algorithm with tiered confidence scoring, and a deliberately calm UI for a domain that's usually anything but.

Licensed under the [MIT License](LICENSE). Issues, forks, and pull requests are welcome if you'd like to build on it.
