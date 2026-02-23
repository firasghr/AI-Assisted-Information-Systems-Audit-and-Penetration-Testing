/**
 * normalizer.js - Vulnerability normalization module.
 *
 * Purpose:
 *   Reads raw scan results from Nmap and OWASP ZAP, converts them into a
 *   unified vulnerability format, deduplicates entries, and persists the
 *   result to data/processed/.
 *
 * Unified Vulnerability Format:
 *   {
 *     id,             // Deterministic UUID v5 from (source + title + asset)
 *     source,         // "nmap" | "owasp_zap"
 *     title,          // Short human-readable vulnerability name
 *     severity,       // "critical" | "high" | "medium" | "low" | "informational"
 *     cvss_score,     // Numeric CVSS score (estimated if not explicitly provided)
 *     description,    // Full vulnerability description
 *     affected_asset, // IP address or URL of affected asset
 *     confidence,     // "confirmed" | "high" | "medium" | "low"
 *     references,     // Array of reference URLs
 *     raw_data        // Original raw fields for audit trail
 *   }
 *
 * Design decisions:
 *   - A deterministic ID (UUID v5 from SHA-1 hash of stable fields) ensures
 *     that the same vulnerability found in two separate scans generates the
 *     same ID, enabling reliable deduplication and delta analysis.
 *   - CVSS scores for Nmap-detected services are estimated from severity
 *     level because Nmap does not produce CVSS scores natively.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { v5: uuidv5 } = require("uuid");

const logger = require("../utils/logger");
const config = require("../utils/config");

// UUID namespace for deterministic IDs (randomly generated once; fixed)
const UUID_NAMESPACE = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

// ---------------------------------------------------------------------------
// Severity → estimated CVSS score mapping
// Used when a tool does not provide an explicit CVSS score.
// Based on NVD severity bands: https://nvd.nist.gov/vuln-metrics/cvss
// ---------------------------------------------------------------------------
const SEVERITY_TO_CVSS = {
  critical:      9.5,
  high:          7.5,
  medium:        5.0,
  low:           2.5,
  informational: 0.0,
};

// ---------------------------------------------------------------------------
// Severity normalisation maps
// ---------------------------------------------------------------------------
const ZAP_SEVERITY_MAP = {
  High:          "high",
  Medium:        "medium",
  Low:           "low",
  Informational: "informational",
};

// Nmap-detected open ports are rated by common knowledge of the service.
// This is a simplified heuristic for the academic context.
function nmapPortSeverity(port, service) {
  const criticalPorts = new Set([21, 22, 23, 25, 53, 110, 143, 3306, 5432, 6379, 27017]);
  const highPorts = new Set([80, 443, 8080, 8443, 8888]);
  if (criticalPorts.has(port)) return "high";
  if (highPorts.has(port)) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Confidence normalisation
// ---------------------------------------------------------------------------
function normaliseConfidence(raw) {
  const val = String(raw || "").toLowerCase();
  if (["confirmed", "certain", "high", "3"].some((v) => val.includes(v))) return "high";
  if (["medium", "2"].some((v) => val.includes(v))) return "medium";
  if (["low", "1", "tentative"].some((v) => val.includes(v))) return "low";
  return "medium";
}

// ---------------------------------------------------------------------------
// Deterministic ID generator
// ---------------------------------------------------------------------------
function generateId(source, title, asset) {
  const key = `${source}::${title}::${asset}`.toLowerCase();
  return uuidv5(key, UUID_NAMESPACE);
}

// ---------------------------------------------------------------------------
// Nmap normalisation
// ---------------------------------------------------------------------------
function normaliseNmapResult(raw) {
  const normalised = [];

  for (const host of raw.hosts || []) {
    // Each open port becomes a vulnerability entry
    for (const port of host.ports || []) {
      if (port.state !== "open") continue;

      const title = port.service
        ? `Open port ${port.port}/${port.protocol} (${port.service})`
        : `Open port ${port.port}/${port.protocol}`;

      const severity = nmapPortSeverity(port.port, port.service);
      const cvss = SEVERITY_TO_CVSS[severity];

      const description = [
        `An open ${port.protocol.toUpperCase()} port was detected on ${host.ip}:${port.port}.`,
        port.product ? `Service: ${port.product} ${port.version || ""}`.trim() + "." : "",
        port.extra_info ? `Extra info: ${port.extra_info}.` : "",
        port.cpe ? `CPE: ${port.cpe}.` : "",
        host.os_matches?.length
          ? `Detected OS: ${host.os_matches[0].name} (accuracy: ${host.os_matches[0].accuracy}%).`
          : "",
      ]
        .filter(Boolean)
        .join(" ");

      normalised.push({
        id: generateId("nmap", title, host.ip),
        source: "nmap",
        title,
        severity,
        cvss_score: cvss,
        description,
        affected_asset: host.ip,
        confidence: "high", // Nmap direct observation = high confidence
        references: port.cpe ? [`https://nvd.nist.gov/products/cpe/search?keyword=${encodeURIComponent(port.cpe)}`] : [],
        raw_data: { host, port },
      });
    }

    // OS detection finding
    if (host.os_matches?.length) {
      const osName = host.os_matches[0].name;
      const title = `OS Detected: ${osName}`;
      normalised.push({
        id: generateId("nmap", title, host.ip),
        source: "nmap",
        title,
        severity: "informational",
        cvss_score: 0.0,
        description: `Operating system fingerprinting identified the host as running ${osName} (accuracy: ${host.os_matches[0].accuracy}%).`,
        affected_asset: host.ip,
        confidence: host.os_matches[0].accuracy >= 90 ? "high" : "medium",
        references: [],
        raw_data: { host },
      });
    }
  }

  return normalised;
}

// ---------------------------------------------------------------------------
// ZAP normalisation
// ---------------------------------------------------------------------------
function normaliseZapResult(raw) {
  return (raw.vulnerabilities || []).map((vuln) => {
    const severity = ZAP_SEVERITY_MAP[vuln.risk_label] || vuln.severity || "informational";
    const cvss = SEVERITY_TO_CVSS[severity];

    const title = vuln.name || "Unknown Vulnerability";
    const asset = vuln.affected_url || raw.target || "";

    return {
      id: generateId("owasp_zap", title, asset),
      source: "owasp_zap",
      title,
      severity,
      cvss_score: cvss,
      description: vuln.description || "",
      affected_asset: asset,
      confidence: normaliseConfidence(vuln.confidence),
      references: vuln.references || [],
      raw_data: vuln,
    };
  });
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------
function deduplicate(vulnerabilities) {
  const seen = new Map();
  for (const v of vulnerabilities) {
    if (!seen.has(v.id)) {
      seen.set(v.id, v);
    }
  }
  return Array.from(seen.values());
}

// ---------------------------------------------------------------------------
// Read latest scan file from a directory
// ---------------------------------------------------------------------------
function readLatestJson(dir) {
  if (!fs.existsSync(dir)) return null;
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();
  if (!files.length) return null;
  const fp = path.join(dir, files[0]);
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8"));
  } catch (err) {
    logger.warn("Failed to read %s: %s", fp, err.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main normalisation function
// ---------------------------------------------------------------------------
function normalize(nmapData, zapData) {
  const all = [];

  if (nmapData) {
    logger.info("Normalising Nmap results...");
    const nmapVulns = normaliseNmapResult(nmapData);
    logger.info("Nmap findings: %d", nmapVulns.length);
    all.push(...nmapVulns);
  }

  if (zapData) {
    logger.info("Normalising ZAP results...");
    const zapVulns = normaliseZapResult(zapData);
    logger.info("ZAP findings: %d", zapVulns.length);
    all.push(...zapVulns);
  }

  const deduped = deduplicate(all);
  logger.info("Total after deduplication: %d (from %d)", deduped.length, all.length);

  // Sort by severity (critical → informational), then by cvss_score descending
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  deduped.sort((a, b) => {
    const diff = (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    return diff !== 0 ? diff : b.cvss_score - a.cvss_score;
  });

  return deduped;
}

// ---------------------------------------------------------------------------
// CLI / module entry point
// ---------------------------------------------------------------------------
async function main() {
  logger.info("Starting vulnerability normalization...");

  // Load scan results
  const nmapData = readLatestJson(config.paths.nmapDir);
  const zapData = readLatestJson(config.paths.zapDir);

  if (!nmapData && !zapData) {
    logger.warn("No scan results found. Run nmap_scanner.py or zap_scanner.py first.");
    process.exit(0);
  }

  const vulnerabilities = normalize(nmapData, zapData);

  // Persist
  if (!fs.existsSync(config.paths.processedDir)) {
    fs.mkdirSync(config.paths.processedDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outFile = path.join(config.paths.processedDir, `normalised_${timestamp}.json`);

  const output = {
    generated_at: new Date().toISOString(),
    total_vulnerabilities: vulnerabilities.length,
    vulnerabilities,
  };

  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
  logger.info("Normalised results saved to %s", outFile);

  return output;
}

if (require.main === module) {
  main().catch((err) => {
    logger.error("Normalizer failed:", err);
    process.exit(1);
  });
}

module.exports = {
  normalize,
  normaliseNmapResult,
  normaliseZapResult,
  deduplicate,
  generateId,
};
