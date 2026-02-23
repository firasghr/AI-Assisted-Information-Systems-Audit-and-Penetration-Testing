/**
 * logger.js - Structured logging utility using Winston.
 *
 * All modules in this project use this centralised logger to ensure
 * consistent log formatting, level control and optional file persistence.
 */

"use strict";

const { createLogger, format, transports } = require("winston");
const path = require("path");
const fs = require("fs");

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, "..", "..", "logs");

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const logger = createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: format.combine(
    format.timestamp({ format: "YYYY-MM-DDTHH:mm:ssZ" }),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: "ai-pentest" },
  transports: [
    // Human-readable console output
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(
          ({ timestamp, level, message, ...meta }) =>
            `${timestamp} [${level}]: ${message}` +
            (Object.keys(meta).length > 1
              ? ` ${JSON.stringify(meta)}`
              : "")
        )
      ),
    }),
    // JSON log file for machine parsing
    new transports.File({
      filename: path.join(LOG_DIR, "app.log"),
      maxsize: 5 * 1024 * 1024, // 5 MB
      maxFiles: 5,
      tailable: true,
    }),
    // Separate error log
    new transports.File({
      filename: path.join(LOG_DIR, "error.log"),
      level: "error",
    }),
  ],
});

module.exports = logger;
