/**
 * logger.js - Structured logging utility using Winston.
 *
 * Design:
 *   - All modules share this single logger instance via `require`.
 *   - Three file transports are maintained:
 *       system.log  - info-level operational events (scan started/completed, etc.)
 *       error.log   - error-level events only
 *       app.log     - all levels, JSON format, for machine parsing / SIEM ingest
 *   - Console transport uses coloured human-readable format during development.
 *   - Child loggers (via `logger.child({ module })`) add a `module` field to
 *     every log entry, enabling per-module filtering in log aggregators.
 *
 * Structured event helpers:
 *   logger.scanStarted(target, scanType)
 *   logger.scanCompleted(target, scanType, durationMs, findingCount)
 *   logger.aiStarted(count)
 *   logger.aiCompleted(count, durationMs, tokensUsed)
 *
 * These helpers emit a consistent `event` field that can be queried directly
 * in tools like Kibana, Datadog, or CloudWatch Insights.
 */

"use strict";

const { createLogger, format, transports } = require("winston");
const path = require("path");
const fs = require("fs");

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, "..", "..", "logs");

// Ensure log directory exists before attaching file transports
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Shared JSON format used by all file transports
// ---------------------------------------------------------------------------
const jsonFileFormat = format.combine(
  format.timestamp({ format: "YYYY-MM-DDTHH:mm:ssZ" }),
  format.errors({ stack: true }),
  format.json()
);

// ---------------------------------------------------------------------------
// Human-readable console format (coloured, single line)
// ---------------------------------------------------------------------------
const consoleFormat = format.combine(
  format.colorize(),
  format.timestamp({ format: "YYYY-MM-DDTHH:mm:ssZ" }),
  format.printf(({ timestamp, level, message, module: mod, event, ...meta }) => {
    const moduleTag = mod ? ` [${mod}]` : "";
    const eventTag  = event ? ` <${event}>` : "";
    // Only include extra meta when there is meaningful content beyond defaults
    const filtered = Object.fromEntries(
      Object.entries(meta).filter(
        ([k]) => !["service", "splat"].includes(k)
      )
    );
    const extra =
      Object.keys(filtered).length > 0 ? ` ${JSON.stringify(filtered)}` : "";
    return `${timestamp} [${level}]${moduleTag}${eventTag}: ${message}${extra}`;
  })
);

// ---------------------------------------------------------------------------
// Logger instance
// ---------------------------------------------------------------------------
const logger = createLogger({
  level: process.env.LOG_LEVEL || "info",
  defaultMeta: { service: "ai-pentest" },
  transports: [
    // Console — human-readable, coloured
    new transports.Console({ format: consoleFormat }),

    // system.log — info+ operational events (scan lifecycle, AI calls, etc.)
    new transports.File({
      filename: path.join(LOG_DIR, "system.log"),
      level: "info",
      format: jsonFileFormat,
      maxsize: 10 * 1024 * 1024, // 10 MB
      maxFiles: 10,
      tailable: true,
    }),

    // error.log — errors only, for alerting / on-call workflows
    new transports.File({
      filename: path.join(LOG_DIR, "error.log"),
      level: "error",
      format: jsonFileFormat,
      maxsize: 5 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),

    // app.log — all levels in JSON, for SIEM / log aggregation ingest
    new transports.File({
      filename: path.join(LOG_DIR, "app.log"),
      format: jsonFileFormat,
      maxsize: 20 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
  ],
});

// ---------------------------------------------------------------------------
// Structured event helpers
// These emit a consistent `event` field alongside the free-text `message`,
// making it trivial to filter/alert on specific lifecycle events in any
// log aggregation platform.
// ---------------------------------------------------------------------------

/**
 * Log that a scan has started.
 * @param {string} target  - Scan target (IP, hostname, or URL)
 * @param {string} scanType - "nmap" | "zap" | "pipeline"
 */
logger.scanStarted = function scanStarted(target, scanType) {
  logger.info(`Scan started: ${scanType} → ${target}`, {
    event: "scan_started",
    target,
    scan_type: scanType,
  });
};

/**
 * Log that a scan has completed.
 * @param {string} target
 * @param {string} scanType
 * @param {number} durationMs  - Wall-clock duration in milliseconds
 * @param {number} findingCount - Number of raw findings collected
 */
logger.scanCompleted = function scanCompleted(target, scanType, durationMs, findingCount) {
  logger.info(
    `Scan completed: ${scanType} → ${target} | ${findingCount} findings in ${durationMs}ms`,
    {
      event: "scan_completed",
      target,
      scan_type: scanType,
      duration_ms: durationMs,
      finding_count: findingCount,
    }
  );
};

/**
 * Log that AI analysis has started.
 * @param {number} vulnerabilityCount - Number of normalised vulns to analyse
 */
logger.aiStarted = function aiStarted(vulnerabilityCount) {
  logger.info(`AI analysis started for ${vulnerabilityCount} vulnerabilities`, {
    event: "ai_analysis_started",
    vulnerability_count: vulnerabilityCount,
  });
};

/**
 * Log that AI analysis has completed.
 * @param {number} vulnerabilityCount
 * @param {number} durationMs
 * @param {number} tokensUsed - Total LLM tokens consumed
 */
logger.aiCompleted = function aiCompleted(vulnerabilityCount, durationMs, tokensUsed) {
  logger.info(
    `AI analysis completed: ${vulnerabilityCount} vulns | ${durationMs}ms | ${tokensUsed} tokens`,
    {
      event: "ai_analysis_completed",
      vulnerability_count: vulnerabilityCount,
      duration_ms: durationMs,
      tokens_used: tokensUsed,
    }
  );
};

module.exports = logger;
