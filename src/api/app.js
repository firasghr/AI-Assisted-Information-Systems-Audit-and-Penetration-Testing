/**
 * app.js - REST API interface for the AI-Assisted Pentesting System.
 *
 * Exposes endpoints for:
 *   - Triggering scans
 *   - Running AI analysis
 *   - Generating reports
 *   - Retrieving metrics
 *   - Health check
 *
 * Security considerations:
 *   - All endpoints validate required parameters before processing.
 *   - API key authentication should be added before production deployment.
 *   - Scan targets are validated to prevent SSRF in a production context.
 *   - Rate limiting protects all /api/* routes.
 *   - CORS is restricted to CORS_ORIGIN env variable (default: localhost:4000).
 *   - X-Request-Id header enables distributed tracing.
 */

"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { randomUUID } = require("crypto");
const rateLimit = require("express-rate-limit");

const logger = require("../utils/logger");
const config = require("../utils/config");
const { normalize } = require("../normalizer/normalizer");
const { analyzeVulnerabilities } = require("../ai/ai_analyzer");
const { compare } = require("../comparison/comparison_engine");
const { generateReport } = require("../report/report_generator");

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Startup validation — fail fast if configuration is broken
// ---------------------------------------------------------------------------
config.validate(logger);

const app = express();

// ---------------------------------------------------------------------------
// CORS — allow only the configured frontend origin(s)
// Inline implementation avoids adding the `cors` package as a dependency.
// The allowed origins Set is computed once at startup for O(1) per-request
// lookup instead of splitting and iterating on every request.
// ---------------------------------------------------------------------------
const allowedOrigins = new Set(
  config.cors.origin.split(",").map((s) => s.trim()).filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (config.cors.origin === "*" || allowedOrigins.has(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: "100kb" }));

// ---------------------------------------------------------------------------
// Rate limiting — required to protect system-command and filesystem endpoints
// ---------------------------------------------------------------------------
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,                   // max 60 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});

// Apply rate limiting to all /api routes
app.use("/api", apiLimiter);

// ---------------------------------------------------------------------------
// Middleware: assign X-Request-Id and log method + path + status + duration
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  const requestId = randomUUID();
  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);

  const startMs = Date.now();
  res.on("finish", () => {
    logger.info(`${req.method} ${req.path} → ${res.statusCode} (${Date.now() - startMs}ms)`, {
      request_id: requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Date.now() - startMs,
    });
  });
  next();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function readLatestFile(dir, prefix) {
  if (!fs.existsSync(dir)) return null;
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.startsWith(prefix) && f.endsWith(".json"))
    .sort()
    .reverse();
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
  });
});

// ---------------------------------------------------------------------------
// POST /api/scan/nmap
// Body: { target, ports?, args? }
// ---------------------------------------------------------------------------
app.post("/api/scan/nmap", async (req, res) => {
  const { target, ports = "1-1024", args = "-sV -O" } = req.body;

  if (!target) {
    return res.status(400).json({ error: "target is required" });
  }

  logger.scanStarted(target, "nmap");
  const t0 = Date.now();

  try {
    const scriptPath = path.join(__dirname, "..", "scanner", "nmap_scanner.py");
    const { stdout, stderr } = await execFileAsync("python3", [
      scriptPath,
      target,
      "--ports", ports,
      "--args", args,
    ]);

    if (stderr) logger.warn("Nmap stderr: %s", stderr);
    const result = JSON.parse(stdout);
    const hostCount = result.hosts ? result.hosts.length : 0;
    logger.scanCompleted(target, "nmap", Date.now() - t0, hostCount);
    res.json(result);
  } catch (err) {
    logger.error("Nmap scan failed: %s", err.message, { event: "scan_error", target, scan_type: "nmap" });
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/scan/zap
// Body: { target_url, zap_url?, api_key? }
// ---------------------------------------------------------------------------
app.post("/api/scan/zap", async (req, res) => {
  const {
    target_url,
    zap_url = config.zap.baseUrl,
    api_key = config.zap.apiKey,
  } = req.body;

  if (!target_url) {
    return res.status(400).json({ error: "target_url is required" });
  }

  logger.scanStarted(target_url, "zap");
  const t0 = Date.now();

  try {
    const scriptPath = path.join(__dirname, "..", "scanner", "zap_scanner.py");
    const { stdout, stderr } = await execFileAsync("python3", [
      scriptPath,
      target_url,
      "--zap-url", zap_url,
      "--api-key", api_key,
    ]);

    if (stderr) logger.warn("ZAP stderr: %s", stderr);
    const result = JSON.parse(stdout);
    const vulnCount = result.vulnerabilities ? result.vulnerabilities.length : 0;
    logger.scanCompleted(target_url, "zap", Date.now() - t0, vulnCount);
    res.json(result);
  } catch (err) {
    logger.error("ZAP scan failed: %s", err.message, { event: "scan_error", target: target_url, scan_type: "zap" });
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/normalize
// Reads latest Nmap + ZAP results and normalises them.
// ---------------------------------------------------------------------------
app.post("/api/normalize", async (req, res) => {
  try {
    const nmapData = readLatestFile(config.paths.nmapDir, "nmap_");
    const zapData = readLatestFile(config.paths.zapDir, "zap_");

    if (!nmapData && !zapData) {
      return res.status(404).json({ error: "No scan results found. Run scans first." });
    }

    const vulnerabilities = normalize(nmapData, zapData);

    const output = {
      generated_at: new Date().toISOString(),
      total_vulnerabilities: vulnerabilities.length,
      vulnerabilities,
    };

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const outFile = path.join(config.paths.processedDir, `normalised_${timestamp}.json`);
    if (!fs.existsSync(config.paths.processedDir)) {
      fs.mkdirSync(config.paths.processedDir, { recursive: true });
    }
    fs.writeFileSync(outFile, JSON.stringify(output, null, 2));

    res.json(output);
  } catch (err) {
    logger.error("Normalization failed: %s", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/analyze
// Sends normalised vulnerabilities to the AI model.
// ---------------------------------------------------------------------------
app.post("/api/analyze", async (req, res) => {
  try {
    const data = readLatestFile(config.paths.processedDir, "normalised_");
    if (!data) {
      return res.status(404).json({ error: "No normalised data found. Run /api/normalize first." });
    }

    logger.aiStarted(data.vulnerabilities.length);
    const t0 = Date.now();

    const { enriched, metrics } = await analyzeVulnerabilities(data.vulnerabilities);

    logger.aiCompleted(enriched.length, Date.now() - t0, metrics?.total_tokens || 0);

    const output = {
      generated_at: new Date().toISOString(),
      metrics,
      total_vulnerabilities: enriched.length,
      vulnerabilities: enriched,
    };

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const outFile = path.join(config.paths.processedDir, `ai_analysis_${timestamp}.json`);
    fs.writeFileSync(outFile, JSON.stringify(output, null, 2));

    res.json(output);
  } catch (err) {
    logger.error("AI analysis failed: %s", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/compare
// Generates comparison metrics between traditional and AI analysis.
// ---------------------------------------------------------------------------
app.post("/api/compare", async (req, res) => {
  try {
    const data = readLatestFile(config.paths.processedDir, "ai_analysis_");
    if (!data) {
      return res.status(404).json({ error: "No AI analysis found. Run /api/analyze first." });
    }

    const metrics = compare(data.vulnerabilities, data.metrics);

    const outFile = path.join(config.paths.processedDir, "metrics.json");
    fs.writeFileSync(outFile, JSON.stringify(metrics, null, 2));

    res.json(metrics);
  } catch (err) {
    logger.error("Comparison failed: %s", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/report
// Generates the PDF report.
// ---------------------------------------------------------------------------
app.post("/api/report", async (req, res) => {
  try {
    const aiData = readLatestFile(config.paths.processedDir, "ai_analysis_");
    const metricsData = readLatestFile(config.paths.processedDir, "metrics");
    const nmapRaw = readLatestFile(config.paths.nmapDir, "nmap_");
    const zapRaw = readLatestFile(config.paths.zapDir, "zap_");

    if (!aiData) {
      return res.status(404).json({ error: "No AI analysis data found." });
    }

    const reportPath = await generateReport(
      aiData.vulnerabilities,
      metricsData,
      nmapRaw,
      zapRaw
    );

    res.json({ report_path: reportPath, message: "Report generated successfully." });
  } catch (err) {
    logger.error("Report generation failed: %s", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/metrics
// Returns the latest comparison metrics.
// ---------------------------------------------------------------------------
app.get("/api/metrics", (_req, res) => {
  const metrics = readLatestFile(config.paths.processedDir, "metrics");
  if (!metrics) {
    return res.status(404).json({ error: "No metrics found. Run /api/compare first." });
  }
  res.json(metrics);
});

// ---------------------------------------------------------------------------
// GET /api/metrics/:scanId
// Returns comparison metrics for a specific scan.
// Looks for a scan-specific metrics file first (metrics_<scanId>.json), then
// falls back to the shared metrics.json for the single-pipeline-run case.
// ---------------------------------------------------------------------------
app.get("/api/metrics/:scanId", (req, res) => {
  const { scanId } = req.params;
  if (!scanId || !/^[\w-]+$/.test(scanId)) {
    return res.status(400).json({ error: "Invalid scanId" });
  }
  const dir = config.paths.processedDir;
  // Try scan-specific file first
  const specific = path.join(dir, `metrics_${scanId}.json`);
  if (fs.existsSync(specific)) {
    try {
      return res.json(JSON.parse(fs.readFileSync(specific, "utf8")));
    } catch { /* fall through */ }
  }
  // Fall back to global metrics.json
  const metricsData = readLatestFile(dir, "metrics");
  if (!metricsData) {
    return res.status(404).json({ error: "No metrics found for this scan." });
  }
  res.json(metricsData);
});

// ---------------------------------------------------------------------------
// GET /api/vulnerabilities
// Returns the latest vulnerability list.
// ---------------------------------------------------------------------------
app.get("/api/vulnerabilities", (_req, res) => {
  const data = readLatestFile(config.paths.processedDir, "ai_analysis_") ||
               readLatestFile(config.paths.processedDir, "normalised_");
  if (!data) {
    return res.status(404).json({ error: "No vulnerability data found." });
  }
  res.json(data);
});

// ---------------------------------------------------------------------------
// Helper: find the PDF report closest to a given scan timestamp.
// Each pipeline run produces one ai_analysis file and one PDF in sequence.
// We match them by chronological index position (i-th scan → i-th report).
// ---------------------------------------------------------------------------
function findReportForScan(scanId, allScanIds) {
  const reportsDir = config.paths.reportsDir || path.join(process.cwd(), "reports");
  if (!fs.existsSync(reportsDir)) return null;

  const pdfs = fs.readdirSync(reportsDir)
    .filter((f) => f.startsWith("pentest_report_") && f.endsWith(".pdf"))
    .sort(); // ascending chronological order

  if (pdfs.length === 0) return null;

  // Use the same positional index as the scan in the ordered scan list
  const idx = allScanIds.indexOf(scanId);
  if (idx === -1) return path.join(reportsDir, pdfs[pdfs.length - 1]);

  // Clamp to available reports; later scans without reports get the newest
  const pdfIdx = Math.min(idx, pdfs.length - 1);
  return path.join(reportsDir, pdfs[pdfIdx]);
}

// ---------------------------------------------------------------------------
// GET /api/scans
// Returns a list of all scan summaries derived from processed data files.
// ---------------------------------------------------------------------------
app.get("/api/scans", (_req, res) => {
  try {
    const dir = config.paths.processedDir;
    if (!fs.existsSync(dir)) {
      return res.json([]);
    }

    // Collect all ai_analysis files (one per pipeline run), sorted ascending
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.startsWith("ai_analysis_") && f.endsWith(".json"))
      .sort();

    // Build ordered scan ID list for positional report matching
    const allScanIds = files.map((f) =>
      f.replace(/^ai_analysis_/, "").replace(/\.json$/, "")
    );

    const scans = files.map((file, fileIdx) => {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
        const scanId = allScanIds[fileIdx];

        // Count severities
        const severityCount = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
        (data.vulnerabilities || []).forEach((v) => {
          const sev = (v.severity || "informational").toLowerCase();
          if (sev in severityCount) severityCount[sev]++;
        });

        // Try scan-specific metrics first, fall back to global
        const metricsData = (() => {
          try {
            const specific = path.join(dir, `metrics_${scanId}.json`);
            if (fs.existsSync(specific)) return JSON.parse(fs.readFileSync(specific, "utf8"));
            const global = path.join(dir, "metrics.json");
            return fs.existsSync(global)
              ? JSON.parse(fs.readFileSync(global, "utf8"))
              : null;
          } catch { return null; }
        })();

        const reportPath = findReportForScan(scanId, allScanIds);

        return {
          id: scanId,
          target: data.target || metricsData?.target || "unknown",
          timestamp: data.generated_at || new Date(0).toISOString(),
          duration: metricsData?.ai_processing_time_seconds
            ? Math.round(metricsData.ai_processing_time_seconds)
            : 0,
          vulnerability_count: (data.vulnerabilities || []).length,
          status: "complete",
          severity_summary: severityCount,
          report_path: reportPath,
        };
      } catch {
        return null;
      }
    }).filter(Boolean);

    res.json(scans);
  } catch (err) {
    logger.error("Failed to list scans: %s", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/scans/:id
// Returns full scan detail (vulnerabilities + metrics + report path) for a
// specific scan identified by its timestamp-based ID.
// ---------------------------------------------------------------------------
app.get("/api/scans/:id", (req, res) => {
  const { id } = req.params;
  if (!id || !/^[\w-]+$/.test(id)) {
    return res.status(400).json({ error: "Invalid scan ID" });
  }

  try {
    const dir = config.paths.processedDir;
    const file = path.join(dir, `ai_analysis_${id}.json`);

    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: "Scan not found." });
    }

    const data = JSON.parse(fs.readFileSync(file, "utf8"));

    const severityCount = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    (data.vulnerabilities || []).forEach((v) => {
      const sev = (v.severity || "informational").toLowerCase();
      if (sev in severityCount) severityCount[sev]++;
    });

    // Try scan-specific metrics first, fall back to global
    const metricsData = (() => {
      const specific = path.join(dir, `metrics_${id}.json`);
      if (fs.existsSync(specific)) {
        try { return JSON.parse(fs.readFileSync(specific, "utf8")); } catch { /* fall through */ }
      }
      return readLatestFile(dir, "metrics");
    })();

    // Build allScanIds for positional report matching
    const allScanIds = fs.existsSync(dir)
      ? fs.readdirSync(dir)
          .filter((f) => f.startsWith("ai_analysis_") && f.endsWith(".json"))
          .sort()
          .map((f) => f.replace(/^ai_analysis_/, "").replace(/\.json$/, ""))
      : [];

    const reportPath = findReportForScan(id, allScanIds);

    res.json({
      id,
      target: data.target || metricsData?.target || "unknown",
      timestamp: data.generated_at || new Date(0).toISOString(),
      duration: metricsData?.ai_processing_time_seconds
        ? Math.round(metricsData.ai_processing_time_seconds)
        : 0,
      vulnerability_count: (data.vulnerabilities || []).length,
      status: "complete",
      severity_summary: severityCount,
      vulnerabilities: data.vulnerabilities || [],
      metrics: metricsData || null,
      report_path: reportPath,
    });
  } catch (err) {
    logger.error("Failed to get scan %s: %s", id, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/report/:scanId
// Returns report metadata (path, generated_at) for a specific scan.
// Uses positional matching: the i-th scan corresponds to the i-th PDF report.
// ---------------------------------------------------------------------------
app.get("/api/report/:scanId", (req, res) => {
  const { scanId } = req.params;
  if (!scanId || !/^[\w-]+$/.test(scanId)) {
    return res.status(400).json({ error: "Invalid scanId" });
  }

  try {
    // Build ordered scan list for positional matching
    const dir = config.paths.processedDir;
    const allScanIds = fs.existsSync(dir)
      ? fs.readdirSync(dir)
          .filter((f) => f.startsWith("ai_analysis_") && f.endsWith(".json"))
          .sort()
          .map((f) => f.replace(/^ai_analysis_/, "").replace(/\.json$/, ""))
      : [];

    const reportPath = findReportForScan(scanId, allScanIds);

    if (!reportPath) {
      return res.status(404).json({ error: "No report available for this scan." });
    }

    const stat = fs.statSync(reportPath);
    res.json({
      report_path: reportPath,
      message: "Report available.",
      generated_at: stat.mtime.toISOString(),
    });
  } catch (err) {
    logger.error("Failed to get report for scan %s: %s", scanId, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/pipeline
// Run the full pipeline: normalize → analyze → compare → report
// ---------------------------------------------------------------------------
app.post("/api/pipeline", async (req, res) => {
  try {
    logger.info("Starting full pipeline execution...", { event: "pipeline_started" });

    // 1. Normalize
    const nmapData = readLatestFile(config.paths.nmapDir, "nmap_");
    const zapData = readLatestFile(config.paths.zapDir, "zap_");

    if (!nmapData && !zapData) {
      return res.status(404).json({ error: "No scan results found. Run scans first." });
    }

    const vulnerabilities = normalize(nmapData, zapData);
    logger.info("Step 1/4: Normalized %d vulnerabilities", vulnerabilities.length);

    // 2. AI Analysis
    logger.aiStarted(vulnerabilities.length);
    const t0 = Date.now();
    const { enriched, metrics: aiMetrics } = await analyzeVulnerabilities(vulnerabilities);
    logger.aiCompleted(enriched.length, Date.now() - t0, aiMetrics?.total_tokens || 0);

    // 3. Compare
    const comparisonMetrics = compare(enriched, aiMetrics);
    logger.info("Step 3/4: Comparison complete");

    // 4. Generate Report
    const reportPath = await generateReport(enriched, comparisonMetrics, nmapData, zapData);
    logger.info("Step 4/4: Report generated at %s", reportPath, { event: "pipeline_completed" });

    res.json({
      status: "complete",
      vulnerabilities_found: enriched.length,
      report_path: reportPath,
      metrics: comparisonMetrics,
    });
  } catch (err) {
    logger.error("Pipeline failed: %s", err.message, { event: "pipeline_error" });
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 404 handler
// ---------------------------------------------------------------------------
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ---------------------------------------------------------------------------
// Error handler — never expose stack traces to clients
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  logger.error("Unhandled error: %s", err.message, { stack: err.stack });
  res.status(500).json({ error: "Internal server error" });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
if (require.main === module) {
  const port = config.server.port;
  app.listen(port, () => {
    logger.info("AI-Assisted Pentesting API running on port %d", port, { event: "server_started", port });
    logger.info("Endpoints: GET /health, POST /api/scan/nmap, POST /api/scan/zap,");
    logger.info("           POST /api/normalize, POST /api/analyze, POST /api/compare,");
    logger.info("           POST /api/report, POST /api/pipeline, GET /api/metrics,");
    logger.info("           GET /api/vulnerabilities, GET /api/scans, GET /api/scans/:id,");
    logger.info("           GET /api/metrics/:scanId, GET /api/report/:scanId");
  });
}

module.exports = app;
