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
 *   - Rate limiting should be added for public-facing deployments.
 */

"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const { execFile } = require("child_process");
const { promisify } = require("util");
const rateLimit = require("express-rate-limit");

const logger = require("../utils/logger");
const config = require("../utils/config");
const { normalize } = require("../normalizer/normalizer");
const { analyzeVulnerabilities } = require("../ai/ai_analyzer");
const { compare } = require("../comparison/comparison_engine");
const { generateReport } = require("../report/report_generator");

const execFileAsync = promisify(execFile);

const app = express();
app.use(express.json());

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
// Middleware: request logging
// ---------------------------------------------------------------------------
app.use((req, _res, next) => {
  logger.info("%s %s", req.method, req.path);
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

  logger.info("Starting Nmap scan for %s", target);

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
    res.json(result);
  } catch (err) {
    logger.error("Nmap scan failed: %s", err.message);
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

  logger.info("Starting ZAP scan for %s", target_url);

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
    res.json(result);
  } catch (err) {
    logger.error("ZAP scan failed: %s", err.message);
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

    const { enriched, metrics } = await analyzeVulnerabilities(data.vulnerabilities);

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
// POST /api/pipeline
// Run the full pipeline: normalize → analyze → compare → report
// ---------------------------------------------------------------------------
app.post("/api/pipeline", async (req, res) => {
  try {
    logger.info("Starting full pipeline execution...");

    // 1. Normalize
    const nmapData = readLatestFile(config.paths.nmapDir, "nmap_");
    const zapData = readLatestFile(config.paths.zapDir, "zap_");

    if (!nmapData && !zapData) {
      return res.status(404).json({ error: "No scan results found. Run scans first." });
    }

    const vulnerabilities = normalize(nmapData, zapData);
    logger.info("Step 1/4: Normalized %d vulnerabilities", vulnerabilities.length);

    // 2. AI Analysis
    const { enriched, metrics: aiMetrics } = await analyzeVulnerabilities(vulnerabilities);
    logger.info("Step 2/4: AI analysis complete");

    // 3. Compare
    const comparisonMetrics = compare(enriched, aiMetrics);
    logger.info("Step 3/4: Comparison complete");

    // 4. Generate Report
    const reportPath = await generateReport(enriched, comparisonMetrics, nmapData, zapData);
    logger.info("Step 4/4: Report generated at %s", reportPath);

    res.json({
      status: "complete",
      vulnerabilities_found: enriched.length,
      report_path: reportPath,
      metrics: comparisonMetrics,
    });
  } catch (err) {
    logger.error("Pipeline failed: %s", err.message);
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
// Error handler
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  logger.error("Unhandled error: %s", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
if (require.main === module) {
  const port = config.server.port;
  app.listen(port, () => {
    logger.info("AI-Assisted Pentesting API running on port %d", port);
    logger.info("Endpoints: GET /health, POST /api/scan/nmap, POST /api/scan/zap,");
    logger.info("           POST /api/normalize, POST /api/analyze, POST /api/compare,");
    logger.info("           POST /api/report, POST /api/pipeline, GET /api/metrics");
  });
}

module.exports = app;
