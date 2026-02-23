/**
 * report_generator.js - Professional PDF report generator using PDFKit.
 *
 * Generates a structured penetration testing report covering:
 *   1.  Executive Summary
 *   2.  Scope
 *   3.  Methodology
 *   4.  Tools Used
 *   5.  Findings (Traditional CVSS-based)
 *   6.  Findings (AI-Assisted)
 *   7.  Risk Comparison Table
 *   8.  Recommendations
 *   9.  Conclusion
 *   10. Appendix (Raw Data Reference)
 *
 * Design decisions:
 *   - PDFKit is used because it provides a programmatic, code-driven API
 *     that is easy to version-control and integrate into a CI/CD pipeline.
 *   - Severity colours follow industry conventions:
 *       Critical: #8B0000 (dark red)
 *       High:     #CC3300
 *       Medium:   #FF8800
 *       Low:      #2255CC
 *       Info:     #444444
 *   - Each section starts on a new page for readability.
 *   - Tables are drawn using PDFKit primitives for maximum portability.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

const logger = require("../utils/logger");
const config = require("../utils/config");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SEVERITY_COLORS = {
  critical:      "#8B0000",
  high:          "#CC3300",
  medium:        "#FF8800",
  low:           "#2255CC",
  informational: "#444444",
};

const PAGE_MARGIN = 50;
const PAGE_WIDTH = 595.28; // A4 width in points
const CONTENT_WIDTH = PAGE_WIDTH - 2 * PAGE_MARGIN;

// ---------------------------------------------------------------------------
// Helper: Ensure directory exists
// ---------------------------------------------------------------------------
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// PDF drawing helpers
// ---------------------------------------------------------------------------

/** Add a full-width horizontal rule */
function hr(doc, y) {
  const _y = y !== undefined ? y : doc.y;
  doc.save().moveTo(PAGE_MARGIN, _y).lineTo(PAGE_WIDTH - PAGE_MARGIN, _y)
    .lineWidth(0.5).strokeColor("#CCCCCC").stroke().restore();
  doc.moveDown(0.3);
}

/** Section heading */
function sectionTitle(doc, text) {
  doc.addPage();
  doc
    .font("Helvetica-Bold")
    .fontSize(16)
    .fillColor("#1A1A2E")
    .text(text, PAGE_MARGIN, PAGE_MARGIN + 20);
  doc.moveDown(0.5);
  hr(doc);
}

/** Subsection heading */
function subsectionTitle(doc, text) {
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").fontSize(12).fillColor("#1A1A2E").text(text);
  doc.moveDown(0.3);
}

/** Body paragraph */
function bodyText(doc, text) {
  doc.font("Helvetica").fontSize(10).fillColor("#333333").text(text, { align: "justify" });
  doc.moveDown(0.4);
}

/** Coloured severity badge text */
function severityText(doc, severity) {
  const color = SEVERITY_COLORS[severity] || "#444444";
  const label = (severity || "unknown").toUpperCase();
  doc.font("Helvetica-Bold").fontSize(9).fillColor(color).text(label, { continued: false });
  doc.fillColor("#333333");
}

/** Simple two-column key-value line */
function kvLine(doc, key, value) {
  doc.font("Helvetica-Bold").fontSize(10).fillColor("#333333").text(`${key}: `, { continued: true });
  doc.font("Helvetica").text(String(value || "N/A"));
}

/**
 * Draw a table.
 * @param {PDFDocument} doc
 * @param {string[]} headers
 * @param {string[][]} rows
 * @param {number[]} colWidths - Column widths in points (must sum ≤ CONTENT_WIDTH)
 * @param {function} [cellColor] - Optional function(row, col) => color string
 */
function drawTable(doc, headers, rows, colWidths, cellColor) {
  const rowHeight = 18;
  const startX = PAGE_MARGIN;
  let y = doc.y;

  // Helper to draw a single row
  function drawRow(cells, isHeader, rowIdx) {
    const bgColor = isHeader ? "#1A1A2E" : rowIdx % 2 === 0 ? "#F8F8F8" : "#FFFFFF";
    const textColor = isHeader ? "#FFFFFF" : "#333333";

    let x = startX;
    let maxHeight = rowHeight;

    // Measure text heights first
    const heights = cells.map((cell, ci) => {
      const w = colWidths[ci] - 8;
      const h = doc.heightOfString(String(cell || ""), { width: w, fontSize: 9 });
      return Math.max(rowHeight, h + 8);
    });
    maxHeight = Math.max(...heights);

    // Check for page overflow
    if (y + maxHeight > doc.page.height - PAGE_MARGIN) {
      doc.addPage();
      y = PAGE_MARGIN;
    }

    // Draw cells
    cells.forEach((cell, ci) => {
      const w = colWidths[ci];
      const fg = cellColor ? (cellColor(rowIdx, ci) || textColor) : textColor;

      doc.save()
        .rect(x, y, w, maxHeight)
        .fill(bgColor)
        .restore();

      // Cell border
      doc.save()
        .rect(x, y, w, maxHeight)
        .lineWidth(0.3)
        .strokeColor("#CCCCCC")
        .stroke()
        .restore();

      doc.save()
        .font(isHeader ? "Helvetica-Bold" : "Helvetica")
        .fontSize(9)
        .fillColor(fg)
        .text(String(cell || ""), x + 4, y + 4, { width: w - 8, height: maxHeight - 4, ellipsis: true });
      doc.restore();

      x += w;
    });

    y += maxHeight;
  }

  drawRow(headers, true, -1);
  rows.forEach((row, i) => drawRow(row, false, i));

  doc.y = y + 4;
}

// ---------------------------------------------------------------------------
// Cover page
// ---------------------------------------------------------------------------
function addCoverPage(doc, reportMeta) {
  doc
    .rect(0, 0, PAGE_WIDTH, 280)
    .fill("#1A1A2E");

  doc
    .font("Helvetica-Bold")
    .fontSize(24)
    .fillColor("#FFFFFF")
    .text("AI-Assisted Information Systems", PAGE_MARGIN, 80, { align: "center", width: CONTENT_WIDTH })
    .text("Audit and Penetration Testing", { align: "center" });

  doc
    .font("Helvetica")
    .fontSize(14)
    .fillColor("#A0C4FF")
    .text("Security Assessment Report", { align: "center" });

  doc.moveDown(2);

  doc
    .font("Helvetica")
    .fontSize(11)
    .fillColor("#FFFFFF")
    .text(`Target: ${reportMeta.target || "Not specified"}`, { align: "center" })
    .text(`Date: ${new Date(reportMeta.timestamp || Date.now()).toDateString()}`, { align: "center" })
    .text(`Classification: CONFIDENTIAL`, { align: "center" });

  doc.y = 310;
  doc
    .font("Helvetica")
    .fontSize(10)
    .fillColor("#555555")
    .text("This report was generated by the AI-Assisted Pentesting System.", PAGE_MARGIN, 310, { align: "center", width: CONTENT_WIDTH })
    .text("Handle in accordance with your organisation's information security policy.", { align: "center" });
}

// ---------------------------------------------------------------------------
// Table of Contents
// ---------------------------------------------------------------------------
function addToc(doc) {
  doc.addPage();
  doc.font("Helvetica-Bold").fontSize(16).fillColor("#1A1A2E").text("Table of Contents", PAGE_MARGIN, PAGE_MARGIN + 20);
  hr(doc);

  const sections = [
    "1. Executive Summary",
    "2. Scope",
    "3. Methodology",
    "4. Tools Used",
    "5. Traditional Findings",
    "6. AI-Assisted Findings",
    "7. Risk Comparison",
    "8. Recommendations",
    "9. Conclusion",
    "10. Appendix",
  ];

  doc.moveDown(0.5);
  sections.forEach((s) => {
    doc.font("Helvetica").fontSize(11).fillColor("#333333").text(s, PAGE_MARGIN);
    doc.moveDown(0.3);
  });
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

function addExecutiveSummary(doc, vulnerabilities, metrics) {
  sectionTitle(doc, "1. Executive Summary");

  const highCritical = vulnerabilities.filter((v) => ["high", "critical"].includes(v.severity)).length;
  const fpCount = metrics?.false_positives_detected_count || 0;
  const timeSaved = metrics?.time_saved_seconds || 0;

  bodyText(doc,
    `This penetration testing engagement identified ${vulnerabilities.length} unique security findings ` +
    `across the target environment. Of these, ${highCritical} are rated High or Critical severity and ` +
    `require immediate remediation. The assessment employed both traditional CVSS-based analysis and ` +
    `AI-assisted prioritisation to provide comprehensive risk context.`
  );

  bodyText(doc,
    `The AI analysis module detected ${fpCount} probable false positives, improving signal quality for ` +
    `the security team. Compared to manual review, AI-assisted prioritisation saved an estimated ` +
    `${Math.round(timeSaved / 60)} minutes of analyst time, representing a ` +
    `${metrics?.time_saved_percent || 0}% reduction in analysis overhead.`
  );

  subsectionTitle(doc, "Key Findings at a Glance");
  const dist = metrics?.severity_distribution || {};
  const rows = [
    ["Critical", dist.critical || 0],
    ["High",     dist.high     || 0],
    ["Medium",   dist.medium   || 0],
    ["Low",      dist.low      || 0],
    ["Informational", dist.informational || 0],
  ].map(([s, c]) => [s, String(c)]);

  drawTable(doc, ["Severity", "Count"], rows, [200, 100],
    (row, col) => col === 0 ? (SEVERITY_COLORS[rows[row]?.[0]?.toLowerCase()] || "#333333") : null
  );
}

function addScope(doc, reportMeta) {
  sectionTitle(doc, "2. Scope");
  bodyText(doc, "The following assets were included in the scope of this security assessment:");
  kvLine(doc, "Primary Target", reportMeta.target);
  kvLine(doc, "Scan Type", "Network (Nmap) + Web Application (OWASP ZAP)");
  kvLine(doc, "Start Time", new Date(reportMeta.timestamp || Date.now()).toISOString());
  kvLine(doc, "Authorisation", "This assessment was conducted under formal written authorisation.");

  doc.moveDown(0.5);
  bodyText(doc,
    "The scope was limited to the specified target addresses. All scanning was performed from a " +
    "dedicated assessment host. No lateral movement or post-exploitation activities were conducted " +
    "beyond those explicitly scoped."
  );
}

function addMethodology(doc) {
  sectionTitle(doc, "3. Methodology");

  bodyText(doc,
    "This assessment followed the Penetration Testing Execution Standard (PTES) and the OWASP " +
    "Testing Guide v4.2. The engagement was structured in five phases:"
  );

  const phases = [
    ["1. Reconnaissance", "Passive information gathering and OSINT collection."],
    ["2. Scanning & Enumeration", "Active port scanning, service discovery, and OS fingerprinting using Nmap."],
    ["3. Web Application Testing", "Automated active scanning using OWASP ZAP to identify OWASP Top 10 vulnerabilities."],
    ["4. AI Risk Analysis", "Normalised findings submitted to GPT-4o for prioritisation, exploitability assessment, and remediation guidance."],
    ["5. Reporting", "Generation of this structured report with comparison of traditional vs AI-assisted analysis."],
  ];

  phases.forEach(([phase, desc]) => {
    subsectionTitle(doc, phase);
    bodyText(doc, desc);
  });

  bodyText(doc,
    "AI Threat Model: The AI analysis layer uses a large language model (LLM) to enrich findings with " +
    "contextual intelligence. Potential limitations include training data cutoff, hallucination risk, " +
    "and lack of target-specific business context. All AI outputs were post-processed and validated."
  );
}

function addTools(doc) {
  sectionTitle(doc, "4. Tools Used");

  const tools = [
    ["Nmap 7.x", "Network scanner", "Port scanning, service detection, OS fingerprinting"],
    ["OWASP ZAP 2.x", "Web application proxy", "Active web vulnerability scanning"],
    ["GPT-4o (OpenAI)", "Large Language Model", "AI-assisted prioritisation and risk analysis"],
    ["Python 3.x", "Scripting language", "Scanner automation and ML classifier"],
    ["Node.js 18+", "Backend runtime", "Normalisation, API, and report generation"],
    ["scikit-learn", "ML library", "Exploitability classifier training and evaluation"],
  ];

  drawTable(
    doc,
    ["Tool", "Category", "Purpose"],
    tools,
    [120, 130, 240]
  );
}

function addFindings(doc, vulnerabilities, isAi = false) {
  const title = isAi ? "6. AI-Assisted Findings" : "5. Traditional Findings (CVSS-based)";
  sectionTitle(doc, title);

  if (!vulnerabilities || vulnerabilities.length === 0) {
    bodyText(doc, "No findings to display.");
    return;
  }

  // Sort appropriately
  const sorted = isAi
    ? [...vulnerabilities].sort((a, b) => (a.ai_analysis?.priority_rank || 99) - (b.ai_analysis?.priority_rank || 99))
    : [...vulnerabilities].sort((a, b) => b.cvss_score - a.cvss_score);

  // Display top 15 in the report body; rest are in appendix
  const displayed = sorted.slice(0, 15);

  displayed.forEach((v, idx) => {
    if (idx > 0) doc.moveDown(0.5);

    const rank = isAi ? (v.ai_analysis?.priority_rank || idx + 1) : idx + 1;
    const score = isAi ? (v.ai_analysis?.ai_risk_score || v.cvss_score) : v.cvss_score;

    doc.font("Helvetica-Bold").fontSize(11).fillColor("#1A1A2E")
      .text(`#${rank} — ${v.title}`);
    doc.moveDown(0.2);

    const color = SEVERITY_COLORS[v.severity] || "#333333";
    doc.font("Helvetica-Bold").fontSize(9).fillColor(color)
      .text(`${(v.severity || "").toUpperCase()}  |  Score: ${score.toFixed(1)}  |  Asset: ${v.affected_asset}  |  Source: ${v.source}`, { continued: false });
    doc.fillColor("#333333");
    doc.moveDown(0.2);

    doc.font("Helvetica").fontSize(9).fillColor("#444444")
      .text(v.description ? v.description.substring(0, 400) : "No description.", { align: "justify" });

    if (isAi && v.ai_analysis) {
      doc.moveDown(0.2);
      doc.font("Helvetica-Oblique").fontSize(9).fillColor("#555555")
        .text(`AI Remediation: ${(v.ai_analysis.remediation || "").substring(0, 300)}`);
      if (v.ai_analysis.false_positive_probability > 0.3) {
        doc.font("Helvetica-Oblique").fontSize(9).fillColor("#888800")
          .text(`⚠ Possible False Positive (probability: ${(v.ai_analysis.false_positive_probability * 100).toFixed(0)}%): ${v.ai_analysis.false_positive_reason}`);
        doc.fillColor("#333333");
      }
    }

    hr(doc);
  });

  if (sorted.length > 15) {
    bodyText(doc, `... and ${sorted.length - 15} additional findings. See Appendix for full list.`);
  }
}

function addComparison(doc, metrics) {
  sectionTitle(doc, "7. Risk Comparison: Traditional vs AI-Assisted");

  if (!metrics) {
    bodyText(doc, "No comparison metrics available.");
    return;
  }

  subsectionTitle(doc, "Statistical Summary");
  kvLine(doc, "Total Vulnerabilities Analysed", metrics.total_vulnerabilities);
  kvLine(doc, "Kendall's τ (Rank Correlation)", `${metrics.kendall_tau} — ${metrics.kendall_tau_interpretation}`);
  kvLine(doc, "Divergent Rankings", `${metrics.divergent_rankings_count} (${metrics.divergent_rankings_percent}%)`);
  kvLine(doc, "False Positives Detected (AI)", metrics.false_positives_detected_count);
  kvLine(doc, "Probable False Positives", metrics.false_positives_probable_count);
  kvLine(doc, "Traditional Estimated Time", `${Math.round(metrics.traditional_estimated_time_seconds / 60)} min`);
  kvLine(doc, "AI Processing Time", `${metrics.ai_processing_time_seconds.toFixed(1)}s`);
  kvLine(doc, "Time Saved", `${Math.round(metrics.time_saved_seconds / 60)} min (${metrics.time_saved_percent}%)`);
  kvLine(doc, "Average CVSS Score", metrics.avg_cvss_score);
  kvLine(doc, "Average AI Risk Score", metrics.avg_ai_risk_score);

  doc.moveDown(0.5);
  subsectionTitle(doc, "Ranking Comparison Table (Top 15)");

  const rows = (metrics.ranking_comparison || []).slice(0, 15).map((r) => [
    r.title?.substring(0, 40) || "",
    String(r.traditional_rank),
    String(r.ai_rank),
    r.rank_change > 0 ? `↑${r.rank_change}` : r.rank_change < 0 ? `↓${Math.abs(r.rank_change)}` : "—",
    r.cvss_score?.toFixed(1) || "0.0",
    r.ai_risk_score?.toFixed(1) || "0.0",
  ]);

  drawTable(
    doc,
    ["Finding", "Trad.", "AI", "Δ", "CVSS", "AI Score"],
    rows,
    [190, 40, 40, 40, 50, 60]
  );
}

function addRecommendations(doc, vulnerabilities) {
  sectionTitle(doc, "8. Recommendations");

  bodyText(doc, "The following remediation actions are recommended, ordered by AI-assisted priority:");

  const highPriority = vulnerabilities
    .filter((v) => v.ai_analysis?.priority_rank)
    .sort((a, b) => a.ai_analysis.priority_rank - b.ai_analysis.priority_rank)
    .slice(0, 10);

  highPriority.forEach((v, i) => {
    subsectionTitle(doc, `${i + 1}. ${v.title}`);
    bodyText(doc, v.ai_analysis?.remediation || "Refer to vendor advisories and security best practices.");
  });
}

function addConclusion(doc, metrics) {
  sectionTitle(doc, "9. Conclusion");

  bodyText(doc,
    "This assessment demonstrates the synergy between traditional penetration testing techniques " +
    "and AI-assisted analysis. While CVSS-based scoring provides a standardised baseline, the LLM " +
    "analysis layer adds contextual depth that enables more effective prioritisation."
  );

  bodyText(doc,
    `With a Kendall's τ of ${metrics?.kendall_tau || "N/A"}, the AI ranking diverged meaningfully ` +
    `from the traditional CVSS ordering, underscoring that numeric severity scores alone are ` +
    `insufficient to capture real-world exploitability and business risk.`
  );

  bodyText(doc,
    "Future work should include authenticated web application testing, integration with SIEM " +
    "platforms, and longitudinal trending of vulnerability counts over multiple scan cycles."
  );

  subsectionTitle(doc, "Ethical and Legal Considerations");
  bodyText(doc,
    "This assessment was conducted under formal written authorisation. All scanning activities " +
    "were performed in accordance with applicable laws including the Computer Fraud and Abuse Act " +
    "(US), Computer Misuse Act (UK), and equivalent national legislation. AI-generated analysis " +
    "was reviewed by a qualified human analyst before inclusion in this report."
  );
}

function addAppendix(doc, vulnerabilities, nmapRaw, zapRaw) {
  sectionTitle(doc, "10. Appendix");

  subsectionTitle(doc, "A. Full Vulnerability List");
  const rows = vulnerabilities.map((v, i) => [
    String(i + 1),
    v.title?.substring(0, 45) || "",
    v.severity || "",
    String(v.cvss_score?.toFixed(1) || "0.0"),
    v.affected_asset?.substring(0, 30) || "",
  ]);

  drawTable(doc, ["#", "Title", "Severity", "CVSS", "Asset"], rows, [30, 220, 70, 50, 120]);

  subsectionTitle(doc, "B. Scan Metadata");
  if (nmapRaw) {
    kvLine(doc, "Nmap Scan ID", nmapRaw.scan_id || "N/A");
    kvLine(doc, "Nmap Target", nmapRaw.target || "N/A");
    kvLine(doc, "Nmap Execution Time", `${nmapRaw.execution_time_seconds || 0}s`);
  }
  if (zapRaw) {
    kvLine(doc, "ZAP Scan ID", zapRaw.scan_id || "N/A");
    kvLine(doc, "ZAP Target", zapRaw.target || "N/A");
    kvLine(doc, "ZAP Execution Time", `${zapRaw.execution_time_seconds || 0}s`);
    kvLine(doc, "ZAP Total Alerts", zapRaw.total_alerts || 0);
  }
}

// ---------------------------------------------------------------------------
// Main report generation function
// ---------------------------------------------------------------------------
async function generateReport(vulnerabilities, metrics, nmapRaw, zapRaw) {
  const reportsDir = config.paths.reportsDir;
  ensureDir(reportsDir);

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = path.join(reportsDir, `pentest_report_${timestamp}.pdf`);

  const target = nmapRaw?.target || zapRaw?.target || "Multiple targets";
  const reportMeta = {
    target,
    timestamp: new Date().toISOString(),
  };

  logger.info("Generating PDF report to %s...", outputPath);

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margins: { top: PAGE_MARGIN, bottom: PAGE_MARGIN, left: PAGE_MARGIN, right: PAGE_MARGIN },
      info: {
        Title: "Penetration Testing Report",
        Author: "AI-Assisted Pentesting System",
        Subject: "Security Assessment",
      },
    });

    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    try {
      addCoverPage(doc, reportMeta);
      addToc(doc);
      addExecutiveSummary(doc, vulnerabilities, metrics);
      addScope(doc, reportMeta);
      addMethodology(doc);
      addTools(doc);
      addFindings(doc, vulnerabilities, false);
      addFindings(doc, vulnerabilities, true);
      addComparison(doc, metrics);
      addRecommendations(doc, vulnerabilities);
      addConclusion(doc, metrics);
      addAppendix(doc, vulnerabilities, nmapRaw, zapRaw);
    } catch (err) {
      doc.end();
      return reject(err);
    }

    doc.end();
    stream.on("finish", () => {
      logger.info("Report generated: %s (%d bytes)", outputPath, fs.statSync(outputPath).size);
      resolve(outputPath);
    });
    stream.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------
function readLatestFile(dir, prefix) {
  if (!fs.existsSync(dir)) return null;
  const files = fs.readdirSync(dir)
    .filter((f) => f.startsWith(prefix) && f.endsWith(".json"))
    .sort().reverse();
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------
async function main() {
  const aiData = readLatestFile(config.paths.processedDir, "ai_analysis_");
  const metrics = readLatestFile(config.paths.processedDir, "metrics") ||
                  readLatestFile(config.paths.processedDir, "metrics.");
  const nmapRaw = readLatestFile(config.paths.nmapDir, "nmap_");
  const zapRaw = readLatestFile(config.paths.zapDir, "zap_");

  if (!aiData) {
    logger.error("No AI analysis data found. Run ai_analyzer.js first.");
    process.exit(1);
  }

  const metricsData = readLatestFile(config.paths.processedDir, "metrics");

  const outPath = await generateReport(aiData.vulnerabilities, metricsData, nmapRaw, zapRaw);
  console.log(`Report saved: ${outPath}`);
}

if (require.main === module) {
  main().catch((err) => {
    logger.error("Report generation failed:", err);
    process.exit(1);
  });
}

module.exports = { generateReport };
