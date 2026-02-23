# AI-Assisted Information Systems Audit and Penetration Testing

> A production-grade, research-level capstone project that augments traditional penetration testing with AI-driven vulnerability prioritisation, ML-based exploitability prediction, and automated PDF reporting — packaged in a professional Next.js cybersecurity dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)

---

## Key Features

| Feature | Details |
|---|---|
| 🔍 **Automated Scanning** | Nmap (network) + OWASP ZAP (web application) via Python wrappers |
| 🤖 **AI Vulnerability Analysis** | GPT-4o contextual risk scoring, business impact, and remediation |
| 🧠 **ML Exploitability Classifier** | scikit-learn Random Forest trained on CVE-feature dataset |
| 📊 **AI vs CVSS Comparison** | Kendall's τ rank correlation, false-positive reduction, time-to-prioritise |
| 📄 **PDF Report Generation** | 10-section professional pentest report (PDFKit) |
| 🖥️ **Cybersecurity Dashboard** | Next.js 14 real-time dashboard with charts, scan control, and history |
| 🔒 **Security-first API** | Rate limiting, CORS, input validation, request logging (Express.js) |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Next.js Dashboard (Port 4000)                        │
│  /dashboard  /history  /history/[id]  /reports  /status                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │  HTTP REST JSON
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Express.js REST API (Port 3000)                     │
│                           src/api/app.js                                │
│   Rate Limiting · CORS · Request Logging · Input Validation             │
└───┬──────────┬────────────────┬──────────────────┬──────────────────────┘
    │          │                │                  │
    ▼          ▼                ▼                  ▼
┌───────┐ ┌───────────┐ ┌──────────────┐ ┌────────────────────┐
│Scanner│ │Normalizer │ │  AI Analyzer │ │ Comparison Engine  │
│(Py)   │ │(Node.js)  │ │  (Node.js +  │ │ + Report Generator │
│Nmap   │ │UUID v5    │ │   GPT-4o)    │ │ (PDFKit)           │
│ZAP    │ │Dedup      │ └──────┬───────┘ └────────────────────┘
└───┬───┘ └─────┬─────┘        │
    │           │              ▼
    ▼           ▼         OpenAI API
┌───────┐ ┌──────────┐
│data/  │ │data/     │    ┌──────────────────────┐
│raw/   │ │processed/│    │  ML Classifier (Py)   │
└───────┘ └──────────┘    │  scikit-learn RF + LR │
                          └──────────────────────┘
```

### Data Flow

```
Target (IP/URL)
      │
      ▼
[Nmap Scanner] ──JSON──► data/raw/nmap/nmap_<ts>.json
[ZAP Scanner]  ──JSON──► data/raw/zap/zap_<ts>.json
      │
      ▼
[Normalizer] ──► Unified Vulnerability Format ──► data/processed/normalised_<ts>.json
      │
      ▼
[AI Analyzer] ──► GPT-4o ──► Enriched Findings ──► data/processed/ai_analysis_<ts>.json
      │
      ├──► [Comparison Engine] ──► data/processed/metrics.json
      │
      ├──► [Report Generator]  ──► reports/pentest_report_<ts>.pdf
      │
      └──► [ML Classifier]     ──► exploitability predictions
```

---

## Folder Structure

```
.
├── src/                             # Backend source code
│   ├── scanner/
│   │   ├── nmap_scanner.py          # Nmap TCP/SYN/OS/version scan
│   │   └── zap_scanner.py           # OWASP ZAP active web scan
│   ├── normalizer/
│   │   └── normalizer.js            # Unified vulnerability normalisation
│   ├── ai/
│   │   └── ai_analyzer.js           # LLM-based risk analysis (OpenAI GPT-4o)
│   ├── comparison/
│   │   └── comparison_engine.js     # Traditional vs AI-assisted comparison
│   ├── report/
│   │   └── report_generator.js      # Professional PDF report generation
│   ├── ml/
│   │   └── exploitability_classifier.py  # ML exploitability prediction
│   ├── api/
│   │   └── app.js                   # Express.js REST API
│   └── utils/
│       ├── logger.js                # Winston structured logging
│       └── config.js                # Centralised configuration
├── frontend/                        # Next.js 14 dashboard
│   ├── app/
│   │   ├── dashboard/page.tsx       # Main dashboard (scan control + charts)
│   │   ├── history/page.tsx         # Scan history list
│   │   ├── history/[id]/page.tsx    # Scan detail view
│   │   ├── reports/page.tsx         # Report management page
│   │   └── status/page.tsx          # System status page
│   ├── components/
│   │   ├── layout/Sidebar.tsx       # Navigation sidebar
│   │   └── layout/Header.tsx        # Top header with health status
│   ├── services/api.ts              # Centralised API fetch layer
│   └── types/index.ts               # TypeScript interfaces
├── tests/
│   ├── test_normalizer.js           # Normalizer unit tests (Jest)
│   ├── test_comparison.js           # Comparison engine tests (Jest)
│   ├── test_scanner.py              # Scanner tests (pytest)
│   └── test_ml_classifier.py        # ML classifier tests (pytest)
├── docs/
│   ├── architecture.md              # Full system architecture documentation
│   └── evaluation.md                # Academic evaluation report (metrics)
├── data/
│   ├── raw/
│   │   ├── nmap/                    # Raw Nmap JSON output
│   │   └── zap/                     # Raw ZAP JSON output
│   └── processed/                   # Normalised and enriched data
├── reports/                         # Generated PDF reports
├── package.json                     # Node.js dependencies + scripts
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment variable template
└── LICENSE                          # MIT License
```

---

## Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.9+
- **Nmap** (`sudo apt install nmap` or macOS: `brew install nmap`)
- **OWASP ZAP** (optional — required for web app scanning)
- **OpenAI API key** (required for AI analysis)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/firasghr/AI-Assisted-Information-Systems-Audit-and-Penetration-Testing.git
cd AI-Assisted-Information-Systems-Audit-and-Penetration-Testing

# Install Node.js backend dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and fill in OPENAI_API_KEY (and ZAP_API_KEY if using ZAP)

# Install frontend dependencies
cd frontend && npm install && cd ..
```

---

## Running the Project

### Start the Backend API

```bash
npm start
# API available at http://localhost:3000
```

### Start the Frontend Dashboard

```bash
cd frontend
npm run dev
# Dashboard available at http://localhost:4000
```

### Run the Full Pipeline (API)

```bash
# Trigger the complete scan → analyse → compare → report pipeline
curl -X POST http://localhost:3000/api/pipeline \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

---

## Individual Module Usage

### 1. Network Scanning (Nmap)

```bash
python src/scanner/nmap_scanner.py 192.168.1.0/24 --ports 1-1024
```

### 2. Web Application Scanning (OWASP ZAP)

```bash
# Start ZAP in daemon mode first:
# zap.sh -daemon -port 8080 -config api.key=YOUR_KEY

python src/scanner/zap_scanner.py http://target.example.com --api-key YOUR_KEY
```

### 3. Normalize → Analyse → Compare → Report (Node.js scripts)

```bash
node src/normalizer/normalizer.js          # Step 1: normalise scan results
node src/ai/ai_analyzer.js                 # Step 2: AI risk analysis
node src/comparison/comparison_engine.js   # Step 3: compute metrics
node src/report/report_generator.js        # Step 4: generate PDF report
```

### 4. Train ML Classifier

```bash
python src/ml/exploitability_classifier.py
```

---

## REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/scan/nmap` | Run Nmap scan (`body: { target, ports?, args? }`) |
| POST | `/api/scan/zap` | Run ZAP scan (`body: { target_url }`) |
| POST | `/api/normalize` | Normalise latest scan results |
| POST | `/api/analyze` | Run AI analysis on normalised data |
| POST | `/api/compare` | Compute comparison metrics |
| POST | `/api/report` | Generate PDF report |
| POST | `/api/pipeline` | Run full pipeline (`body: { target? }`) |
| GET | `/api/metrics` | Get latest comparison metrics |
| GET | `/api/metrics/:scanId` | Get metrics for a specific scan |
| GET | `/api/vulnerabilities` | Get latest vulnerability list |
| GET | `/api/scans` | Get scan history |
| GET | `/api/scans/:id` | Get full detail for a specific scan |
| GET | `/api/report/:scanId` | Get report info for a specific scan |

### Example: Full pipeline request

```bash
curl -s -X POST http://localhost:3000/api/pipeline \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org"}' | jq '.metrics.kendall_tau'
```

### Example: Fetch vulnerability list

```bash
curl http://localhost:3000/api/vulnerabilities | jq '.vulnerabilities[0]'
```

---

## Dashboard Pages

| Route | Description |
|-------|-------------|
| `/dashboard` | Main control centre: scan launcher, metric cards, vulnerability table, 4 charts, AI vs CVSS analysis, report download |
| `/history` | Paginated scan history with severity breakdown |
| `/history/[id]` | Full detail view for a single past scan |
| `/reports` | Report management: list all reports with PDF download links |
| `/status` | System health: backend status, API endpoints, auto-refresh every 30 s |

---

## Running Tests

```bash
# JavaScript unit tests (Jest)
npm test

# Python unit tests (pytest)
python -m pytest tests/test_scanner.py tests/test_ml_classifier.py -v

# Frontend type-check + build
cd frontend && npm run build
```

---

## Academic Evaluation Summary

This project was evaluated against three quantitative research questions:

### RQ1 — Does AI reorder CVSS-based vulnerability rankings?

| Scenario | Kendall's τ | Interpretation |
|---|---|---|
| Homogeneous severity | 0.45 | Low agreement — AI reprioritises by exploitability context |
| Mixed severity | 0.62 | Moderate agreement |
| Wide severity spread | 0.78 | High agreement — CVSS dominates |

A τ of 0.45–0.62 in real-world scans confirms substantive AI reranking beyond CVSS.

### RQ2 — Does the ML classifier outperform a CVSS threshold?

| Method | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Random Forest | **0.74** | **0.71** | **0.72** | **0.81** |
| Logistic Regression | 0.68 | 0.65 | 0.66 | 0.75 |
| CVSS ≥ 7.0 baseline | 0.61 | 0.72 | 0.66 | 0.74 |

The RF model achieves **+9% F1** and **+13pp precision** over the CVSS threshold baseline.

### RQ3 — How much analyst time does AI prioritisation save?

| n findings | Traditional | AI-Assisted | Saved |
|---|---|---|---|
| 10 | 20 min | ~8 s | ~98% |
| 50 | 100 min | ~25 s | ~99.6% |
| 100 | 200 min | ~45 s | ~99.6% |

Even with 30% human review overhead, AI-assisted prioritisation reduces time-to-prioritise by **>97%**.

> Full methodology, statistical derivations, and threat-to-validity analysis: see [`docs/evaluation.md`](docs/evaluation.md).  
> Full system architecture and design decisions: see [`docs/architecture.md`](docs/architecture.md).

---

## Modules Overview

### Scanner Layer (Python)
- **nmap_scanner.py**: TCP SYN scan, service/version detection, OS fingerprinting
- **zap_scanner.py**: OWASP ZAP spider + active scan with alert normalisation

### Normalisation Layer (Node.js)
- Converts raw Nmap/ZAP output to a unified vulnerability schema
- Deduplication via deterministic UUID v5 IDs (SHA-1 of `source::title::asset`)
- Consistent severity → CVSS estimation; sort order: severity-first

### AI Analysis Layer (Node.js + OpenAI GPT-4o)
- Structured JSON prompting for contextual risk scoring and exploitability assessment
- Business impact analysis, remediation guidance, false-positive detection
- Token counting for cost transparency; temperature = 0.2 for determinism

### Comparison Engine (Node.js)
- Kendall's τ-b rank correlation (handles ties correctly)
- Time-to-prioritise delta; false positive reduction metrics
- Output: `data/processed/metrics.json`

### Report Generator (Node.js + PDFKit)
- Professional 10-section PDF: cover page, executive summary, findings tables, comparison
- Severity colour-coded (Critical=red, High=orange, Medium=amber, Low=green)

### ML Exploitability Classifier (Python + scikit-learn)
- Random Forest (200 trees) + Logistic Regression baseline
- Trained on synthetic 5,000-sample CVE-like dataset; fixed seed for reproducibility
- Stratified 5-fold cross-validation; saved artefacts: `.joblib` files

---

## Security Considerations

1. **Authorisation**: Always obtain written authorisation before scanning any target.
2. **API Key Protection**: Never commit `.env` to version control.
3. **Command Injection**: Uses `execFile` (not `exec`) — arguments are passed as arrays, no shell.
4. **CORS**: Restricted to `CORS_ORIGIN` env variable (default: `http://localhost:4000`).
5. **Rate Limiting**: 60 requests / 15 minutes per IP on all `/api/*` routes.
6. **AI Limitations**: All AI-generated findings must be reviewed by a qualified human analyst.
7. **Data Privacy**: Scan results may contain sensitive system information — handle accordingly.

---

## Academic References

1. FIRST.org. (2023). *CVSS v3.1 Specification Document*. https://www.first.org/cvss/specification-document
2. CISA. (2024). *Known Exploited Vulnerabilities Catalog*. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. National Vulnerability Database. *NVD Data Feeds*. https://nvd.nist.gov/vuln/data-feeds
4. Kendall, M. G. (1938). A new measure of rank correlation. *Biometrika*, 30(1/2), 81–93.
5. Breiman, L. (2001). Random forests. *Machine Learning*, 45(1), 5–32.
6. PTES: Penetration Testing Execution Standard — http://www.pentest-standard.org/
7. OWASP Testing Guide v4.2 — https://owasp.org/www-project-web-security-testing-guide/
8. Goodfellow et al. (2016). *Deep Learning*. MIT Press.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

**Author:** firasghr  
**Repository:** https://github.com/firasghr/AI-Assisted-Information-Systems-Audit-and-Penetration-Testing
