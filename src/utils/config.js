/**
 * config.js - Central configuration module.
 *
 * Loads environment variables from .env (if present) and exposes a single
 * configuration object used throughout the application.
 *
 * Startup validation:
 *   Call config.validate() once at server boot to surface missing or
 *   malformed required variables immediately, rather than failing silently
 *   deep inside a request handler.
 */

"use strict";

require("dotenv").config();
const path = require("path");

const config = {
  // OpenAI
  openai: {
    apiKey: process.env.OPENAI_API_KEY || "",
    model: process.env.OPENAI_MODEL || "gpt-4o",
  },

  // OWASP ZAP
  zap: {
    baseUrl: process.env.ZAP_BASE_URL || "http://localhost:8080",
    apiKey: process.env.ZAP_API_KEY || "",
  },

  // REST API server
  server: {
    port: parseInt(process.env.PORT || "3000", 10),
    env: process.env.NODE_ENV || "development",
  },

  // Data directories
  paths: {
    dataDir: process.env.DATA_DIR || path.join(__dirname, "..", "..", "data"),
    rawDir: process.env.RAW_DATA_DIR || path.join(__dirname, "..", "..", "data", "raw"),
    processedDir:
      process.env.PROCESSED_DATA_DIR ||
      path.join(__dirname, "..", "..", "data", "processed"),
    reportsDir:
      process.env.REPORTS_DIR || path.join(__dirname, "..", "..", "reports"),
    nmapDir:
      process.env.RAW_DATA_DIR
        ? path.join(process.env.RAW_DATA_DIR, "nmap")
        : path.join(__dirname, "..", "..", "data", "raw", "nmap"),
    zapDir:
      process.env.RAW_DATA_DIR
        ? path.join(process.env.RAW_DATA_DIR, "zap")
        : path.join(__dirname, "..", "..", "data", "raw", "zap"),
  },

  // Logging
  logging: {
    level: process.env.LOG_LEVEL || "info",
    dir: process.env.LOG_DIR || path.join(__dirname, "..", "..", "logs"),
  },

  // CORS allowed origin (comma-separated list or single URL)
  cors: {
    origin: process.env.CORS_ORIGIN || "http://localhost:4000",
  },

  /**
   * validate() - Call once at server startup.
   *
   * Emits a warning for each missing optional variable and throws an Error
   * for each missing required variable so the process fails fast with a
   * clear message rather than crashing later with a cryptic error.
   *
   * @param {object} log - Logger instance (must expose .warn and .error)
   */
  validate(log) {
    const warnings = [];
    const errors = [];

    // OpenAI key is required for any AI analysis endpoint
    if (!this.openai.apiKey) {
      warnings.push("OPENAI_API_KEY is not set — AI analysis endpoints will fail");
    }

    // PORT must parse to a valid number
    if (isNaN(this.server.port) || this.server.port < 1 || this.server.port > 65535) {
      errors.push(`PORT="${process.env.PORT}" is not a valid port number (1–65535)`);
    }

    warnings.forEach((msg) => log.warn(`[config] ${msg}`));

    if (errors.length > 0) {
      errors.forEach((msg) => log.error(`[config] ${msg}`));
      throw new Error(
        `Configuration errors at startup:\n  • ${errors.join("\n  • ")}`
      );
    }
  },
};

module.exports = config;
