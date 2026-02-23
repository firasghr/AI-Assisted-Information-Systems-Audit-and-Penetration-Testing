# System Architecture Documentation

**Project:** AI-Assisted Information Systems Audit and Penetration Testing  
**Document type:** Architecture Reference  
**Version:** 1.0  

---

## 1. Overview

This document describes the full architecture of the AI-Assisted Penetration Testing Platform. The system is a multi-layer, polyglot application combining a Python scanning engine, a Node.js backend pipeline, an OpenAI-powered analysis layer, a React/Next.js dashboard, and JSON-file-based intermediate storage.

The design follows the **Clean Architecture** principle: each layer has a single responsibility and communicates with adjacent layers through well-defined interfaces (JSON files or HTTP).

---

## 2. High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Next.js Dashboard (Port 4000)                   │
│  ┌─────────────┐  ┌──────────────────┐  ┌─────────────────────────┐    │
│  │ Scan Control│  │ Vulnerability     │  │ Metrics / Charts /      │    │
│  │   Panel     │  │ Management Table  │  │ Trad vs AI Comparison   │    │
│  └──────┬──────┘  └────────┬─────────┘  └────────────┬────────────┘    │
│         │                  │                          │                  │
│  ┌──────▼──────────────────▼──────────────────────────▼────────────┐    │
│  │              API Service Layer  (services/api.ts)               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │  HTTP (REST JSON)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Express.js REST API (Port 3000)                  │
│                              src/api/app.js                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  Rate Limiter│  │ Req. Logger  │  │ Error Handler│  │  404 Guard │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
│                                                                         │
│  POST /api/scan/nmap     POST /api/scan/zap     POST /api/normalize     │
│  POST /api/analyze       POST /api/compare      POST /api/report        │
│  POST /api/pipeline      GET  /api/metrics       GET /api/vulns         │
└───┬──────────┬────────────────┬──────────────────┬──────────────────────┘
    │          │                │                  │
    ▼          ▼                ▼                  ▼
┌───────┐ ┌───────────┐ ┌──────────────┐ ┌────────────────┐
│Scanner│ │Normalizer │ │  AI Analyzer │ │Comparison Engine│
│Layer  │ │   Layer   │ │    Layer     │ │    + Report     │
│(Py)   │ │  (Node)   │ │   (Node)     │ │    Generator    │
└───┬───┘ └─────┬─────┘ └──────┬───────┘ └───────┬────────┘
    │           │              │                  │
    ▼           ▼              ▼                  ▼
┌───────┐ ┌──────────┐ ┌────────────┐ ┌──────────────────┐
│data/  │ │data/     │ │  OpenAI    │ │  data/processed/ │
│raw/   │ │processed/│  │  GPT-4o   │ │  metrics.json    │
│nmap/  │ │normalised│ │  API       │ │  reports/*.pdf   │
│zap/   │ │*.json    │ └────────────┘ └──────────────────┘
└───────┘ └──────────┘
    │
    ▼
┌──────────────────────┐
│  ML Classifier (Py)  │
│  scikit-learn RF +   │
│  Logistic Regression │
└──────────────────────┘
```

---

## 3. Layer-by-Layer Module Explanation

### 3.1 Scanner Layer  
**Location:** `src/scanner/`  
**Language:** Python 3  
**Purpose:** Data collection — runs real tools and captures raw output as structured JSON

#### 3.1.1 `nmap_scanner.py`

| Property | Value |
|---|---|
| Tool wrapped | Nmap 7.x via `python-nmap` library |
| Scan types | TCP SYN (`-sS`), service detection (`-sV`), OS detection (`-O`) |
| Input | Target IP / hostname, port range, extra Nmap args |
| Output | `data/raw/nmap/nmap_<timestamp>.json` |
| Execution time | Measured and included in output JSON |
| Error handling | `NmapNotInstalledError`, `NmapScanError`, timeout |

**Academic note:** Nmap SYN scanning represents the foundational tool of traditional active reconnaissance. The scanner layer models the manual first step of a penetration tester gathering host and service information.

#### 3.1.2 `zap_scanner.py`

| Property | Value |
|---|---|
| Tool wrapped | OWASP ZAP via REST API (`python-owasp-zap-v2.4`) |
| Scan phases | Spider (crawl) → Active Scan → Alert retrieval |
| Input | Target URL, ZAP API base URL, ZAP API key |
| Output | `data/raw/zap/zap_<timestamp>.json` |
| Alert fields | name, risk, description, URL, CWE ID, confidence, references |
| Poll interval | 5 seconds until `status == 100` |

**Academic note:** OWASP ZAP performs automated web application security testing (DAST). The active scan injects payloads to detect injection, XSS, CSRF, and misconfiguration vulnerabilities — equivalent to the web-application portion of a manual pentest.

---

### 3.2 Normalization Layer  
**Location:** `src/normalizer/normalizer.js`  
**Language:** Node.js  
**Purpose:** Translate heterogeneous scanner outputs into a single canonical vulnerability format

#### Unified Vulnerability Schema

```json
{
  "id":             "UUID v5 (deterministic from source+title+asset)",
  "source":         "nmap | owasp_zap",
  "title":          "Human-readable name",
  "severity":       "critical | high | medium | low | informational",
  "cvss_score":     0.0,
  "description":    "Full description",
  "affected_asset": "IP address or URL",
  "confidence":     "high | medium | low",
  "references":     ["https://..."]
}
```

**Key design decisions:**

- **Deterministic UUIDs (v5):** The ID is a SHA-1 hash of `source::title::asset`. This means the same finding from two separate scans produces the same ID, enabling reliable deduplication and delta tracking across scan runs.
- **Severity → CVSS estimation:** Nmap does not produce CVSS scores. The normalizer applies a conservative mapping (critical=9.5, high=7.5, medium=5.0, low=2.5) to enable consistent downstream scoring.
- **Deduplication:** A `Map<id, vuln>` keeps only the first occurrence; subsequent identical findings are silently dropped.
- **Sort order:** Output is sorted severity-first (critical → informational), CVSS-second. This ensures the AI analysis batch always starts with the highest-risk findings.

---

### 3.3 AI Analysis Layer  
**Location:** `src/ai/ai_analyzer.js`  
**Language:** Node.js  
**Purpose:** Enrich normalised findings with LLM-generated contextual analysis

#### Prompt Strategy

The prompt is structured as a machine-parseable JSON request:

```
You are a senior penetration tester and threat analyst.
Analyse the following vulnerabilities and for each one provide:
  1. priority_rank (integer, 1 = most urgent)
  2. exploitability_score (0–10 float)
  3. business_impact (string)
  4. remediation (specific steps)
  5. false_positive_probability (0.0–1.0 float)
  6. false_positive_reason (string)
  7. severity_justification (string)
  8. ai_risk_score (0–10 float)

Return ONLY valid JSON: { "analyses": [...] }
```

**Key design decisions:**

- **Chunk size = 10:** Limits token usage per API call and prevents context-window overflow. Large finding lists are split into chunks and results are merged.
- **Temperature = 0.2:** Low temperature reduces randomness and hallucination risk for structured analysis tasks.
- **JSON-only output:** The prompt explicitly forbids prose to make parsing deterministic. Output is JSON-parsed; parse failures trigger a retry.
- **Token counting:** Total tokens consumed are logged and included in the metrics output for cost tracking.

**Security consideration — prompt injection:** Vulnerability titles and descriptions from scanner output could theoretically contain adversarial prompt text. The normalizer strips all HTML/script content. The AI output is JSON-parsed and not executed, limiting injection impact to data pollution rather than code execution.

---

### 3.4 Comparison Engine  
**Location:** `src/comparison/comparison_engine.js`  
**Language:** Node.js  
**Purpose:** Quantify the difference between CVSS-based and AI-based prioritisation

#### Metrics produced

| Metric | Implementation | Purpose |
|---|---|---|
| Kendall's τ-b | O(n²) pair comparison | Rank correlation between CVSS and AI ordering |
| Prioritisation divergence | Rank delta > 1 position | % of findings AI moved from CVSS order |
| False positive count | fp_probability > 0.5 | Noise reduction quantification |
| Time-to-prioritise delta | (n × 120s − AI_ms) / (n × 120s) | Analyst efficiency gain |
| Average CVSS vs AI risk | Arithmetic mean | Score calibration comparison |

**See `docs/evaluation.md` for detailed statistical methodology.**

---

### 3.5 Report Generator  
**Location:** `src/report/report_generator.js`  
**Language:** Node.js  
**Purpose:** Produce a professional, multi-section PDF pentest report

#### Report Structure

1. Cover page (title, target, timestamp, classification)
2. Executive Summary
3. Scope and Methodology
4. Tools Used
5. Findings — Traditional (CVSS-ranked table)
6. Findings — AI-Assisted (AI-ranked table with business impact)
7. Risk Comparison Table (side-by-side CVSS vs AI rank)
8. Recommendations
9. Conclusion
10. Appendix — Raw scan data

**Colour coding:** Critical=red `#DC2626`, High=orange `#EA580C`, Medium=amber `#D97706`, Low=green `#16A34A`, Informational=grey `#6B7280`

---

### 3.6 ML Exploitability Classifier  
**Location:** `src/ml/exploitability_classifier.py`  
**Language:** Python 3 / scikit-learn  
**Purpose:** Predict vulnerability exploitability as an independent AI signal

The classifier trains two models:

| Model | Rationale |
|---|---|
| Random Forest (200 trees) | High accuracy, handles non-linearity, provides feature importances |
| Logistic Regression | Interpretable baseline, fast inference, requires feature scaling |

**CV strategy:** Stratified 5-fold cross-validation preserves class balance in each fold, producing a robust F1 estimate with standard deviation.

**Saved artefacts:** `data/processed/models/random_forest_exploitability.joblib`, `feature_scaler.joblib`

---

### 3.7 REST API  
**Location:** `src/api/app.js`  
**Language:** Node.js / Express 4  
**Purpose:** Orchestrate the full pipeline and expose all capabilities via HTTP

#### Endpoint Reference

| Method | Path | Description |
|---|---|---|
| GET | /health | Health check |
| POST | /api/scan/nmap | Trigger Nmap scan |
| POST | /api/scan/zap | Trigger ZAP scan |
| POST | /api/normalize | Normalize latest scan results |
| POST | /api/analyze | Run AI analysis on normalized data |
| POST | /api/compare | Compute comparison metrics |
| POST | /api/report | Generate PDF report |
| POST | /api/pipeline | Run full pipeline (normalize → analyze → compare → report) |
| GET | /api/metrics | Retrieve latest metrics |
| GET | /api/vulnerabilities | Retrieve latest vulnerability list |

#### Security middleware stack

```
Request
   │
   ├─► express-rate-limit (60 req / 15 min per IP on /api/*)
   ├─► express.json() with 100kb limit
   ├─► request logger (method, path, status, duration)
   ├─► Target validation (allowlist: IPs + registered hostnames)
   └─► Route handlers
          │
          └─► Error handler (500, no stack traces in production)
```

---

### 3.8 Dashboard (Frontend)  
**Location:** `frontend/`  
**Language:** TypeScript / Next.js 14 (App Router)  
**Purpose:** Professional, real-time cybersecurity platform UI

#### Component Tree

```
app/
├── layout.tsx              Root layout (font, theme)
├── page.tsx                Landing → redirect to /dashboard
├── dashboard/
│   └── page.tsx            Main dashboard (metrics, charts, scan control)
└── history/
    ├── page.tsx             Scan history list
    └── [id]/
        └── page.tsx         Scan detail view

components/
├── layout/
│   ├── Sidebar.tsx          Navigation sidebar
│   └── Header.tsx           Top header with status
└── history/
    ├── ScanHistoryTable.tsx  History table component
    └── SeveritySummaryBadges.tsx  Severity count badges

services/
└── api.ts                  Centralised fetch wrapper + all API functions

types/
└── index.ts                All TypeScript interfaces
```

---

## 4. Data Flow Diagram

```
                         ┌──────────────────┐
  Operator/Analyst ─────►│  Next.js          │
                         │  Dashboard        │
                         │  (Port 4000)      │
                         └────────┬──────────┘
                                  │ POST /api/scan/nmap
                                  │ POST /api/pipeline
                                  │ GET /api/vulnerabilities
                                  │ GET /api/metrics
                                  ▼
                         ┌──────────────────┐
                         │  Express REST API │
                         │  (Port 3000)      │
                         └──┬───────────┬───┘
                            │           │
          ┌─────────────────▼──┐    ┌───▼─────────────────┐
          │  Python Scanner     │    │  Node.js Pipeline    │
          │  subprocess (sync)  │    │  (async/await)       │
          └──┬──────────┬───────┘    └──┬──────────────────┘
             │          │              │
         ┌───▼──┐  ┌────▼────┐        │
         │ nmap │  │OWASP ZAP│        │
         │  CLI │  │ REST API│        │
         └───┬──┘  └────┬────┘        │
             │          │             │
         ┌───▼──────────▼──┐          │
         │  data/raw/       │          │
         │  nmap/*.json     ◄──────────┘ (read by Normalizer)
         │  zap/*.json      │
         └──────────────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  Normalizer       │  ──► data/processed/normalised_*.json
         │  (normalizer.js)  │
         └──────────────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  AI Analyzer      │  ──► OpenAI GPT-4o (HTTPS)
         │  (ai_analyzer.js) │       └──► data/processed/ai_analysis_*.json
         └──────────────────┘
                  │
          ┌───────┴────────┐
          │                │
          ▼                ▼
 ┌────────────────┐  ┌─────────────────┐
 │ Comparison     │  │  Report Gen     │
 │ Engine         │  │  (PDFKit)       │
 │ metrics.json   │  │  reports/*.pdf  │
 └────────────────┘  └─────────────────┘
```

---

## 5. Security Architecture

### 5.1 Input Validation

All user-controlled inputs pass through a validation layer before reaching the filesystem or subprocess calls:

| Input | Validation |
|---|---|
| `target` (scan target) | Regex: valid IPv4/IPv6 or hostname; rejects shell metacharacters |
| `ports` | Regex: `^\d+(-\d+)?(,\d+(-\d+)?)*$` |
| `args` | Allowlist of safe Nmap flags |
| `target_url` | URL parse; rejects non-http(s) schemes; rejects private IP ranges for ZAP |

### 5.2 Command Injection Prevention

Subprocess calls use `execFile` (not `exec` or `spawn` with shell), passing arguments as an array. This prevents shell injection because no shell interpreter is invoked:

```javascript
// Safe: arguments are passed as array, no shell expansion
await execFileAsync("python3", [scriptPath, target, "--ports", ports]);

// Unsafe (never used): shell interprets metacharacters
// exec(`python3 ${scriptPath} ${target}`)
```

### 5.3 File System Isolation

- All output files are written to `data/` subdirectories with fixed prefixes
- No user input is used in file path construction
- `readLatestFile()` filters filenames by prefix and `.json` extension before reading

### 5.4 API Security

| Layer | Control |
|---|---|
| Rate limiting | 60 requests / 15 min per IP (express-rate-limit) |
| Body size limit | `express.json({ limit: "100kb" })` |
| Response headers | Security headers via Helmet (CSP, HSTS, X-Frame-Options) |
| Error messages | Stack traces never sent to client in production |
| CORS | Configurable allowlist via `CORS_ORIGIN` env variable |

### 5.5 Secret Management

All secrets (OpenAI API key, ZAP API key) are loaded exclusively from environment variables. The `.env` file is `.gitignore`'d. The `.env.example` contains only placeholder values.

---

## 6. Scalability and Performance Considerations

### 6.1 Current Architecture (MVP)

| Dimension | Current approach | Limitation |
|---|---|---|
| Storage | JSON files on local disk | Not queryable; no history |
| Concurrency | Single-process Node.js | One active pipeline at a time |
| AI calls | Sequential chunked calls | Bottleneck for large scan sets |
| Scan execution | Blocking subprocess | API blocks while scanner runs |

### 6.2 Production Upgrade Path

| Concern | Recommended upgrade |
|---|---|
| Storage | PostgreSQL + Prisma ORM (scan history, vulnerability persistence) |
| Concurrency | Job queue (Bull/BullMQ + Redis) for async scan execution |
| AI throughput | Parallel chunk processing with `Promise.all` + retry logic |
| Authentication | JWT middleware protecting `/api/*` routes |
| Containerisation | Docker Compose (backend + frontend + PostgreSQL + Redis) |
| Observability | Structured Winston logs → ELK stack or Datadog |

---

## 7. Module Interaction Summary

```
┌────────────┬────────────────────────────┬───────────────────────────────┐
│ Module     │ Inputs                     │ Outputs                       │
├────────────┼────────────────────────────┼───────────────────────────────┤
│ nmap_scan  │ target IP, port range      │ data/raw/nmap/nmap_*.json     │
│ zap_scan   │ target URL, ZAP URL        │ data/raw/zap/zap_*.json       │
│ normalizer │ nmap_*.json, zap_*.json    │ data/processed/normalised_*.json│
│ ai_analyzer│ normalised_*.json          │ data/processed/ai_analysis_*.json│
│ comparison │ ai_analysis_*.json         │ data/processed/metrics.json   │
│ report_gen │ ai_analysis + metrics      │ reports/pentest_report_*.pdf  │
│ ml_class.  │ vulnerability features     │ exploitability predictions    │
│ api/app.js │ HTTP requests              │ JSON responses, orchestration │
│ dashboard  │ API responses              │ UI rendered to browser        │
└────────────┴────────────────────────────┴───────────────────────────────┘
```

---

## 8. Dependency Reference

### Backend (Node.js)

| Package | Version | Purpose |
|---|---|---|
| express | ^4.18.2 | HTTP server framework |
| express-rate-limit | ^7.1.5 | Rate limiting middleware |
| openai | ^4.20.0 | GPT-4o API client |
| pdfkit | ^0.14.0 | PDF generation |
| winston | ^3.11.0 | Structured logging |
| uuid | ^9.0.0 | UUID v5 deterministic IDs |
| dotenv | ^16.3.1 | Environment variable loading |
| axios | ^1.6.0 | HTTP client (ZAP API) |

### Frontend (Next.js)

| Package | Version | Purpose |
|---|---|---|
| next | 14.x | React framework (App Router) |
| react / react-dom | ^18 | UI framework |
| tailwindcss | ^3.4 | Utility-first CSS |
| recharts | ^3.7 | Data visualisation |
| lucide-react | latest | Icon library |
| @radix-ui/* | various | Accessible UI primitives |

### Python

| Package | Version | Purpose |
|---|---|---|
| python-nmap | 0.7.1 | Nmap subprocess wrapper |
| python-owasp-zap-v2.4 | 0.0.21 | ZAP REST API client |
| scikit-learn | 1.3.2 | ML classifiers |
| pandas / numpy | latest | Data processing |
| joblib | 1.3.2 | Model serialisation |
| pytest | 7.4.3 | Test framework |
