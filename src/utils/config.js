/**
 * config.js - Central configuration module.
 *
 * Loads environment variables from .env (if present) and exposes a single
 * configuration object used throughout the application. Using a centralised
 * config module makes it easy to validate required secrets at startup.
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
};

module.exports = config;
