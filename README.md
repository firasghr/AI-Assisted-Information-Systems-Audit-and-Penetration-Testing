# AI-Assisted Information Systems Audit and Penetration Testing

A university-level capstone project implementing a production-grade, modular AI-assisted penetration testing and security audit system.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    REST API (Express.js)                         │
│                      src/api/app.js                             │
└────────┬──────────────┬──────────────┬──────────────┬──────────┘
         │              │              │              │
   ┌─────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐ ┌────▼──────────┐
   │  Scanner   │ │Normalizer  │ │AI Analysis│ │   Report Gen  │
   │   Layer    │ │   Layer    │ │   Layer   │ │     Layer     │
   │  (Python)  │ │  (Node.js) │ │ (Node.js) │ │   (Node.js)   │
   └─────┬──────┘ └─────┬──────┘ └────┬──────┘ └────┬──────────┘
         │              │              │              │
   ┌─────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐ ┌────▼──────────┐
   │Nmap Scanner│ │ Unified    │ │  OpenAI   │ │  PDFKit PDF   │
   │ZAP Scanner │ │Vuln Format │ │  GPT-4o   │ │  Generation   │
   └─────┬──────┘ └─────┬──────┘ └────┬──────┘ └───────────────┘
         │              │              │
   ┌─────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐
   │data/raw/   │ │data/       │ │Comparison │
   │nmap/ zap/  │ │processed/  │ │  Engine   │
   └────────────┘ └────────────┘ └───────────┘
                                       │
                               ┌───────▼───────┐
                               │  ML Classifier│
                               │  (Python/     │
                               │  scikit-learn)│
                               └───────────────┘
```

### Data Flow

```
Target (IP/URL)
      │
      ▼
[Nmap Scanner] ──JSON──► data/raw/nmap/
[ZAP Scanner]  ──JSON──► data/raw/zap/
      │
      ▼
[Normalizer] ──► Unified Vulnerability Format ──► data/processed/normalised_*.json
      │
      ▼
[AI Analyzer] ──► OpenAI GPT-4o ──► Enriched Findings ──► data/processed/ai_analysis_*.json
      │
      ├──► [Comparison Engine] ──► data/processed/metrics.json
      │
      ├──► [Report Generator] ──► reports/pentest_report_*.pdf
      │
      └──► [ML Classifier] ──► Exploitability predictions
```

---

## Folder Structure

```
.
├── src/
│   ├── scanner/
│   │   ├── nmap_scanner.py          # Nmap TCP/SYN/OS/version scan
│   │   └── zap_scanner.py           # OWASP ZAP active web scan
│   ├── normalizer/
│   │   └── normalizer.js            # Unified vulnerability normalization
│   ├── ai/
│   │   └── ai_analyzer.js           # LLM-based risk analysis (OpenAI)
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
│       └── config.js                # Centralized configuration
├── tests/
│   ├── test_normalizer.js           # Normalizer unit tests (Jest)
│   ├── test_comparison.js           # Comparison engine tests (Jest)
│   ├── test_scanner.py              # Scanner tests (pytest)
│   └── test_ml_classifier.py        # ML classifier tests (pytest)
├── data/
│   ├── raw/
│   │   ├── nmap/                    # Raw Nmap JSON output
│   │   └── zap/                     # Raw ZAP JSON output
│   └── processed/                   # Normalised and enriched data
├── reports/                         # Generated PDF reports
├── package.json
├── requirements.txt
└── .env.example
```

---

## Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.9+
- **Nmap** installed on the system (`sudo apt install nmap` or equivalent)
- **OWASP ZAP** running in daemon mode (for web application scanning)
- **OpenAI API key** (for AI analysis)

---

## Installation

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

---

## Usage

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

### 3. Normalize Results
```bash
node src/normalizer/normalizer.js
```

### 4. Run AI Analysis
```bash
node src/ai/ai_analyzer.js
```

### 5. Generate Comparison Metrics
```bash
node src/comparison/comparison_engine.js
```

### 6. Generate PDF Report
```bash
node src/report/report_generator.js
```

### 7. Train ML Classifier
```bash
python src/ml/exploitability_classifier.py
```

### 8. Start REST API
```bash
npm start
# API available at http://localhost:3000
```

### 9. Full Pipeline via API
```bash
curl -X POST http://localhost:3000/api/pipeline
```

---

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/scan/nmap` | Run Nmap scan |
| POST | `/api/scan/zap` | Run ZAP scan |
| POST | `/api/normalize` | Normalize scan results |
| POST | `/api/analyze` | Run AI analysis |
| POST | `/api/compare` | Generate comparison metrics |
| POST | `/api/report` | Generate PDF report |
| POST | `/api/pipeline` | Run complete pipeline |
| GET | `/api/metrics` | Get latest metrics |
| GET | `/api/vulnerabilities` | Get latest vulnerability list |

---

## Running Tests

```bash
# JavaScript tests (Jest)
npm test

# Python tests (pytest)
python -m pytest tests/test_scanner.py tests/test_ml_classifier.py -v
```

---

## Security Considerations

1. **Authorisation**: Always obtain written authorisation before scanning any target.
2. **API Key Protection**: Never commit `.env` to version control.
3. **AI Limitations**: All AI-generated analysis must be reviewed by a qualified human analyst.
4. **Data Privacy**: Scan results may contain sensitive system information — handle accordingly.
5. **Rate Limiting**: Add rate limiting to the REST API before any public deployment.

---

## Modules Overview

### Scanner Layer (Python)
- **nmap_scanner.py**: TCP SYN scan, service/version detection, OS fingerprinting
- **zap_scanner.py**: OWASP ZAP spider + active scan with alert normalisation

### Normalization Layer (Node.js)
- Converts raw Nmap/ZAP output to unified vulnerability format
- Deduplication via deterministic UUID v5 IDs
- Consistent severity mapping and CVSS estimation

### AI Analysis Layer (Node.js + OpenAI)
- Structured LLM prompting for prioritisation and exploitability assessment
- Business impact analysis and remediation guidance
- False positive detection with probability scoring

### Comparison Engine (Node.js)
- Kendall's τ rank correlation between CVSS and AI rankings
- Time-to-prioritise comparison (estimated manual vs AI)
- False positive detection metrics

### Report Generator (Node.js + PDFKit)
- Professional 10-section PDF with cover page, TOC, findings, and comparison tables
- Severity colour-coded findings
- Executive summary with key statistics

### ML Classifier (Python + scikit-learn)
- Random Forest and Logistic Regression classifiers
- Trained on synthetic CVE-like dataset (2000–5000 samples)
- Evaluated with precision, recall, F1 score, and ROC-AUC
- 5-fold cross-validation for robustness

---

## Academic References

- PTES: Penetration Testing Execution Standard — http://www.pentest-standard.org/
- OWASP Testing Guide v4.2 — https://owasp.org/www-project-web-security-testing-guide/
- CVSS v3.1 Specification — https://www.first.org/cvss/specification-document
- NVD Vulnerability Database — https://nvd.nist.gov/
- Goodfellow et al. (2016). *Deep Learning*. MIT Press.
