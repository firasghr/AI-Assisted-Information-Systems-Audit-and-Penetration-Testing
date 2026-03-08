/**
 * report_generator.js - Professional PDF report generator using PDFKit.
 *
 * Generates a structured penetration testing report covering:
 *   1.  Cover Page
 *   2.  Table of Contents
 *   3.  Executive Summary
 *   4.  Scope & Engagement Details
 *   5.  Methodology
 *   6.  Tools Used
 *   7.  Findings — Traditional CVSS-based
 *   8.  Findings — AI-Assisted
 *   9.  Risk Comparison (AI vs Traditional)
 *   10. Recommendations
 *   11. Conclusion
 *   12. Appendix
 */

"use strict";

const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

const logger = require("../utils/logger");
const config = require("../utils/config");

// ---------------------------------------------------------------------------
// Design Tokens
// ---------------------------------------------------------------------------
const COLORS = {
  navy:       "#0F172A",
  darkSlate:  "#1E293B",
  slate600:   "#475569",
  slate400:   "#94A3B8",
  slate200:   "#E2E8F0",
  slate50:    "#F8FAFC",
  white:      "#FFFFFF",
  blue600:    "#2563EB",
  blue100:    "#DBEAFE",
  accent:     "#3B82F6",
  critical:   "#DC2626",
  high:       "#EA580C",
  medium:     "#CA8A04",
  low:        "#16A34A",
  info:       "#64748B",
};

const SEVERITY_COLORS = {
  critical:      COLORS.critical,
  high:          COLORS.high,
  medium:        COLORS.medium,
  low:           COLORS.low,
  informational: COLORS.info,
};

const PAGE_MARGIN = 54;
const PAGE_WIDTH = 595.28;   // A4
const PAGE_HEIGHT = 841.89;  // A4
const CONTENT_WIDTH = PAGE_WIDTH - 2 * PAGE_MARGIN;
const FOOTER_Y = PAGE_HEIGHT - 36;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function safeStr(val, fallback) {
  fallback = fallback || "N/A";
  if (val === null || val === undefined) return fallback;
  return String(val);
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.substring(0, len - 1) + "..." : str;
}

// ---------------------------------------------------------------------------
// Page-level helpers
// ---------------------------------------------------------------------------

/** Add page footer with page number and classification */
function addFooter(doc, pageNum) {
  doc.save();
  doc.moveTo(PAGE_MARGIN, FOOTER_Y - 8)
     .lineTo(PAGE_WIDTH - PAGE_MARGIN, FOOTER_Y - 8)
     .lineWidth(0.4).strokeColor(COLORS.slate200).stroke();
  doc.font("Helvetica").fontSize(7).fillColor(COLORS.slate400)
     .text("CONFIDENTIAL - AI-Assisted Penetration Testing Report", PAGE_MARGIN, FOOTER_Y, { lineBreak: false });
  doc.text("Page " + pageNum, PAGE_WIDTH - PAGE_MARGIN - 60, FOOTER_Y, { width: 60, align: "right", lineBreak: false });
  doc.restore();
}

/** Start a new section page with title */
function sectionPage(doc, title, pageCounter) {
  doc.addPage();
  pageCounter.n++;

  // Blue accent bar at top
  doc.save()
     .rect(PAGE_MARGIN, PAGE_MARGIN, 4, 22).fill(COLORS.accent)
     .restore();

  doc.font("Helvetica-Bold").fontSize(18).fillColor(COLORS.navy)
     .text(title, PAGE_MARGIN + 14, PAGE_MARGIN + 1);

  doc.moveDown(0.4);

  // Separator line
  doc.save()
     .moveTo(PAGE_MARGIN, doc.y)
     .lineTo(PAGE_WIDTH - PAGE_MARGIN, doc.y)
     .lineWidth(0.6).strokeColor(COLORS.slate200).stroke()
     .restore();

  doc.moveDown(0.6);
  addFooter(doc, pageCounter.n);
}

/** Sub-section heading */
function subHeading(doc, text) {
  checkPageSpace(doc, 40);
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").fontSize(12).fillColor(COLORS.darkSlate).text(text);
  doc.moveDown(0.25);
}

/** Body paragraph */
function body(doc, text) {
  doc.font("Helvetica").fontSize(9.5).fillColor(COLORS.slate600)
     .text(text, { align: "justify", lineGap: 2 });
  doc.moveDown(0.3);
}

/** Key-value line */
function kv(doc, key, value) {
  doc.font("Helvetica-Bold").fontSize(9.5).fillColor(COLORS.darkSlate)
     .text(key + ":  ", { continued: true });
  doc.font("Helvetica").fillColor(COLORS.slate600).text(safeStr(value));
}

/** Horizontal rule */
function hr(doc) {
  var y = doc.y;
  doc.save()
     .moveTo(PAGE_MARGIN, y)
     .lineTo(PAGE_WIDTH - PAGE_MARGIN, y)
     .lineWidth(0.3).strokeColor(COLORS.slate200).stroke()
     .restore();
  doc.moveDown(0.3);
}

/** Check remaining space and add page if needed */
function checkPageSpace(doc, needed) {
  if (doc.y + needed > PAGE_HEIGHT - PAGE_MARGIN - 50) {
    doc.addPage();
  }
}

// ---------------------------------------------------------------------------
// Table drawing - production quality with zebra rows, proper overflow
// ---------------------------------------------------------------------------
function drawTable(doc, headers, rows, colWidths, opts) {
  opts = opts || {};
  var headerBg = opts.headerBg || COLORS.navy;
  var headerFg = opts.headerFg || COLORS.white;
  var zebraA = opts.zebraA || COLORS.white;
  var zebraB = opts.zebraB || COLORS.slate50;
  var fontSize = opts.fontSize || 8;
  var rowPadding = opts.rowPadding || 5;
  var cellColor = opts.cellColor || null;
  var startX = PAGE_MARGIN;

  function measureRowHeight(cells) {
    var heights = cells.map(function(cell, ci) {
      var w = colWidths[ci] - 8;
      return doc.heightOfString(safeStr(cell), { width: w, fontSize: fontSize }) + 2 * rowPadding;
    });
    var max = 18;
    for (var i = 0; i < heights.length; i++) {
      if (heights[i] > max) max = heights[i];
    }
    return max;
  }

  function drawRow(cells, y, isHeader, rowIdx) {
    var h = measureRowHeight(cells);
    var x = startX;

    for (var ci = 0; ci < cells.length; ci++) {
      var cell = cells[ci];
      var w = colWidths[ci];
      var bg = isHeader ? headerBg : rowIdx % 2 === 0 ? zebraA : zebraB;
      var fg;
      if (cellColor && !isHeader) {
        fg = cellColor(rowIdx, ci) || COLORS.slate600;
      } else if (isHeader) {
        fg = headerFg;
      } else {
        fg = COLORS.slate600;
      }

      // Background
      doc.save().rect(x, y, w, h).fill(bg).restore();
      // Border
      doc.save().rect(x, y, w, h).lineWidth(0.3).strokeColor(COLORS.slate200).stroke().restore();
      // Text
      doc.save()
         .font(isHeader ? "Helvetica-Bold" : "Helvetica")
         .fontSize(fontSize)
         .fillColor(fg)
         .text(safeStr(cell), x + 4, y + rowPadding, {
           width: w - 8, height: h - rowPadding, ellipsis: true,
         });
      doc.restore();
      x += w;
    }

    return h;
  }

  var y = doc.y;

  // Header
  if (y + 20 > PAGE_HEIGHT - PAGE_MARGIN - 50) { doc.addPage(); y = PAGE_MARGIN; }
  var headerH = drawRow(headers, y, true, -1);
  y += headerH;

  // Data rows
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var h = measureRowHeight(row);
    if (y + h > PAGE_HEIGHT - PAGE_MARGIN - 50) {
      doc.addPage();
      y = PAGE_MARGIN;
      var hh = drawRow(headers, y, true, -1);
      y += hh;
    }
    var rh = drawRow(row, y, false, i);
    y += rh;
  }

  doc.y = y + 6;
}

// ---------------------------------------------------------------------------
// Stat box - small rounded rectangle with label + value
// ---------------------------------------------------------------------------
function statBox(doc, x, y, w, h, label, value, color) {
  doc.save().roundedRect(x, y, w, h, 4).fill(COLORS.slate50).restore();
  doc.save().rect(x, y, 3, h).fill(color).restore();
  doc.save().font("Helvetica").fontSize(7).fillColor(COLORS.slate400)
     .text(label, x + 10, y + 6, { width: w - 14 });
  doc.restore();
  doc.save().font("Helvetica-Bold").fontSize(14).fillColor(COLORS.darkSlate)
     .text(safeStr(value), x + 10, y + 18, { width: w - 14 });
  doc.restore();
}

// ---------------------------------------------------------------------------
// Cover Page
// ---------------------------------------------------------------------------
function addCoverPage(doc, meta) {
  // Full-width navy header block
  doc.rect(0, 0, PAGE_WIDTH, 320).fill(COLORS.navy);

  // Accent line
  doc.save()
     .moveTo(PAGE_MARGIN, 60).lineTo(PAGE_MARGIN + 60, 60)
     .lineWidth(3).strokeColor(COLORS.accent).stroke()
     .restore();

  doc.font("Helvetica-Bold").fontSize(28).fillColor(COLORS.white)
     .text("Security Assessment", PAGE_MARGIN, 78, { width: CONTENT_WIDTH });
  doc.font("Helvetica-Bold").fontSize(28).fillColor(COLORS.accent)
     .text("Report", PAGE_MARGIN, doc.y, { width: CONTENT_WIDTH });

  doc.moveDown(1.2);
  doc.font("Helvetica").fontSize(12).fillColor(COLORS.slate200)
     .text("AI-Assisted Information Systems Audit", PAGE_MARGIN)
     .text("& Penetration Testing Platform", PAGE_MARGIN);

  doc.moveDown(1.5);
  var metaY = doc.y;
  doc.font("Helvetica").fontSize(9).fillColor(COLORS.slate400);
  doc.text("TARGET", PAGE_MARGIN, metaY);
  doc.font("Helvetica-Bold").fontSize(11).fillColor(COLORS.white);
  doc.text(meta.target || "Not specified", PAGE_MARGIN, metaY + 12);

  doc.font("Helvetica").fontSize(9).fillColor(COLORS.slate400);
  doc.text("DATE", PAGE_MARGIN + 250, metaY);
  doc.font("Helvetica-Bold").fontSize(11).fillColor(COLORS.white);
  doc.text(new Date(meta.timestamp || Date.now()).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  }), PAGE_MARGIN + 250, metaY + 12);

  // Classification ribbon
  doc.save().rect(0, 300, PAGE_WIDTH, 20).fill(COLORS.accent).restore();
  doc.font("Helvetica-Bold").fontSize(8).fillColor(COLORS.white)
     .text("CLASSIFICATION: CONFIDENTIAL", PAGE_MARGIN, 305, { width: CONTENT_WIDTH, align: "center" });

  // Lower section
  doc.y = 360;
  doc.font("Helvetica").fontSize(9).fillColor(COLORS.slate600)
     .text("This report was generated by the AI-Assisted Penetration Testing System.", PAGE_MARGIN, 360, {
       width: CONTENT_WIDTH, align: "center",
     });
  doc.text("Handle in accordance with your organisation's information security policy.", {
    align: "center",
  });

  doc.moveDown(3);

  // Disclaimer box
  var disclaimerY = doc.y;
  doc.save()
     .roundedRect(PAGE_MARGIN, disclaimerY, CONTENT_WIDTH, 65, 4)
     .fill(COLORS.slate50)
     .restore();
  doc.font("Helvetica-Bold").fontSize(8).fillColor(COLORS.darkSlate)
     .text("DISCLAIMER", PAGE_MARGIN + 12, disclaimerY + 10);
  doc.font("Helvetica").fontSize(7.5).fillColor(COLORS.slate600)
     .text(
       "This report contains sensitive security information. Unauthorised disclosure may cause harm. " +
       "Distribution is restricted to authorised personnel only. The findings represent a point-in-time " +
       "assessment and do not guarantee ongoing security posture.",
       PAGE_MARGIN + 12, doc.y + 2, { width: CONTENT_WIDTH - 24 }
     );
}

// ---------------------------------------------------------------------------
// Table of Contents
// ---------------------------------------------------------------------------
function addToc(doc, pageCounter) {
  doc.addPage();
  pageCounter.n++;
  addFooter(doc, pageCounter.n);

  doc.font("Helvetica-Bold").fontSize(18).fillColor(COLORS.navy)
     .text("Table of Contents", PAGE_MARGIN, PAGE_MARGIN + 10);
  doc.moveDown(1);

  var sections = [
    { num: "01", title: "Executive Summary" },
    { num: "02", title: "Scope & Engagement Details" },
    { num: "03", title: "Methodology" },
    { num: "04", title: "Tools Used" },
    { num: "05", title: "Traditional Findings (CVSS)" },
    { num: "06", title: "AI-Assisted Findings" },
    { num: "07", title: "Risk Comparison" },
    { num: "08", title: "Recommendations" },
    { num: "09", title: "Conclusion" },
    { num: "10", title: "Appendix" },
  ];

  for (var i = 0; i < sections.length; i++) {
    var s = sections[i];
    var y = doc.y;
    doc.font("Helvetica-Bold").fontSize(10).fillColor(COLORS.accent)
       .text(s.num, PAGE_MARGIN, y, { continued: false });
    doc.font("Helvetica").fontSize(10).fillColor(COLORS.darkSlate)
       .text(s.title, PAGE_MARGIN + 30, y);

    var lineY = y + 6;
    var titleEndX = PAGE_MARGIN + 30 + doc.widthOfString(s.title) + 8;
    doc.save();
    for (var x = titleEndX; x < PAGE_WIDTH - PAGE_MARGIN - 4; x += 4) {
      doc.circle(x, lineY, 0.5).fill(COLORS.slate200);
    }
    doc.restore();

    doc.moveDown(0.7);
  }
}

// ---------------------------------------------------------------------------
// 1. Executive Summary
// ---------------------------------------------------------------------------
function addExecutiveSummary(doc, vulnerabilities, metrics, pageCounter) {
  sectionPage(doc, "01  Executive Summary", pageCounter);

  var total = vulnerabilities.length;
  var critCount = vulnerabilities.filter(function(v) { return v.severity === "critical"; }).length;
  var highCount = vulnerabilities.filter(function(v) { return v.severity === "high"; }).length;
  var medCount = vulnerabilities.filter(function(v) { return v.severity === "medium"; }).length;
  var lowCount = vulnerabilities.filter(function(v) { return v.severity === "low"; }).length;
  var infoCount = vulnerabilities.filter(function(v) { return v.severity === "informational"; }).length;
  var fpCount = (metrics && metrics.false_positives_detected_count) || 0;
  var timeSaved = (metrics && metrics.time_saved_seconds) || 0;

  body(doc,
    "This penetration testing engagement identified " + total + " unique security findings across the " +
    "target environment. Of these, " + (critCount + highCount) + " are rated High or Critical severity and " +
    "require immediate attention. The assessment employed both traditional CVSS-based analysis and " +
    "AI-assisted prioritisation (GPT-4o) to provide comprehensive risk context."
  );

  body(doc,
    "The AI analysis module detected " + fpCount + " probable false positive(s), improving signal quality " +
    "for the security team. Compared to manual review, AI-assisted prioritisation saved an estimated " +
    Math.round(timeSaved / 60) + " minute(s) of analyst time, representing a " +
    ((metrics && metrics.time_saved_percent) || 0).toFixed(1) + "% reduction in analysis overhead."
  );

  doc.moveDown(0.3);

  // Severity stat boxes
  var boxW = (CONTENT_WIDTH - 4 * 8) / 5;
  var boxY = doc.y;
  var boxes = [
    { label: "CRITICAL", value: critCount, color: COLORS.critical },
    { label: "HIGH",     value: highCount, color: COLORS.high },
    { label: "MEDIUM",   value: medCount,  color: COLORS.medium },
    { label: "LOW",      value: lowCount,  color: COLORS.low },
    { label: "INFO",     value: infoCount, color: COLORS.info },
  ];

  for (var i = 0; i < boxes.length; i++) {
    var b = boxes[i];
    var x = PAGE_MARGIN + i * (boxW + 8);
    statBox(doc, x, boxY, boxW, 42, b.label, b.value, b.color);
  }

  doc.y = boxY + 52;

  // Key metrics row
  subHeading(doc, "Assessment Metrics");
  var metricsBoxW = (CONTENT_WIDTH - 3 * 8) / 4;
  var mBoxY = doc.y;
  var mBoxes = [
    { label: "TOTAL FINDINGS",  value: total,                                                  color: COLORS.accent },
    { label: "KENDALL'S TAU",   value: (metrics && metrics.kendall_tau != null) ? metrics.kendall_tau.toFixed(3) : "N/A", color: COLORS.accent },
    { label: "TIME SAVED",      value: ((metrics && metrics.time_saved_percent) || 0).toFixed(0) + "%", color: COLORS.low },
    { label: "FALSE POSITIVES", value: fpCount,                                                 color: COLORS.high },
  ];

  for (var j = 0; j < mBoxes.length; j++) {
    var mb = mBoxes[j];
    var mx = PAGE_MARGIN + j * (metricsBoxW + 8);
    statBox(doc, mx, mBoxY, metricsBoxW, 42, mb.label, mb.value, mb.color);
  }

  doc.y = mBoxY + 52;
}

// ---------------------------------------------------------------------------
// 2. Scope
// ---------------------------------------------------------------------------
function addScope(doc, meta, pageCounter) {
  sectionPage(doc, "02  Scope & Engagement Details", pageCounter);

  body(doc, "The following assets and parameters defined the scope of this security assessment:");
  doc.moveDown(0.2);

  kv(doc, "Primary Target", meta.target);
  kv(doc, "Assessment Type", "Network (Nmap) + Web Application (OWASP ZAP)");
  kv(doc, "Assessment Date", new Date(meta.timestamp || Date.now()).toISOString());
  kv(doc, "Authorisation", "Conducted under formal written authorisation");
  kv(doc, "Classification", "CONFIDENTIAL");

  doc.moveDown(0.5);
  body(doc,
    "The scope was limited to the specified target addresses. All scanning was performed from a " +
    "dedicated assessment host. No lateral movement or post-exploitation activities were conducted " +
    "beyond those explicitly scoped. Testing was non-destructive and designed to identify " +
    "vulnerabilities without causing service disruption."
  );
}

// ---------------------------------------------------------------------------
// 3. Methodology
// ---------------------------------------------------------------------------
function addMethodology(doc, pageCounter) {
  sectionPage(doc, "03  Methodology", pageCounter);

  body(doc,
    "This assessment followed the Penetration Testing Execution Standard (PTES) and the OWASP " +
    "Testing Guide v4.2. The engagement was structured in five phases:"
  );

  var phases = [
    ["Phase 1 -- Reconnaissance", "Passive information gathering, DNS enumeration, and OSINT collection to identify the target's attack surface."],
    ["Phase 2 -- Scanning & Enumeration", "Active TCP connect scanning using Nmap against common ports, service version detection, and OS fingerprinting."],
    ["Phase 3 -- Web Application Testing", "Automated active scanning using OWASP ZAP to identify OWASP Top 10 vulnerabilities, security header misconfigurations, and sensitive information exposure."],
    ["Phase 4 -- AI Risk Analysis", "Normalised findings submitted to GPT-4o for contextual prioritisation, exploitability assessment, false positive detection, and remediation guidance."],
    ["Phase 5 -- Reporting", "Generation of this structured report with statistical comparison of traditional CVSS-based vs AI-assisted analysis rankings."],
  ];

  for (var i = 0; i < phases.length; i++) {
    checkPageSpace(doc, 50);
    subHeading(doc, phases[i][0]);
    body(doc, phases[i][1]);
  }

  doc.moveDown(0.3);
  subHeading(doc, "AI Model Limitations");
  body(doc,
    "The AI analysis layer uses a large language model (LLM) to enrich findings with contextual " +
    "intelligence. Limitations include training data cutoff, potential for hallucination, and lack " +
    "of target-specific business context. All AI outputs were programmatically validated and " +
    "cross-referenced against the original scan data."
  );
}

// ---------------------------------------------------------------------------
// 4. Tools
// ---------------------------------------------------------------------------
function addTools(doc, pageCounter) {
  sectionPage(doc, "04  Tools Used", pageCounter);

  var tools = [
    ["Nmap 7.x",             "Network Scanner",        "Port scanning, service detection, OS fingerprinting"],
    ["OWASP ZAP 2.x",        "Web Application Proxy",  "Active web vulnerability scanning"],
    ["GPT-4o (OpenAI)",       "Large Language Model",   "AI-assisted prioritisation and risk analysis"],
    ["Python 3.x",           "Automation Runtime",      "Scanner automation and ML classification"],
    ["Node.js 18+",          "Backend Runtime",         "Normalisation, comparison, and report generation"],
    ["PDFKit",               "Report Engine",           "Programmatic PDF generation"],
  ];

  drawTable(doc, ["Tool", "Category", "Purpose"], tools, [130, 120, CONTENT_WIDTH - 250]);
}

// ---------------------------------------------------------------------------
// 5 & 6. Findings
// ---------------------------------------------------------------------------
function addFindings(doc, vulnerabilities, isAi, pageCounter) {
  var num = isAi ? "06" : "05";
  var title = isAi ? (num + "  AI-Assisted Findings") : (num + "  Traditional Findings (CVSS)");
  sectionPage(doc, title, pageCounter);

  if (!vulnerabilities || vulnerabilities.length === 0) {
    body(doc, "No findings to display for this section.");
    return;
  }

  var sorted;
  if (isAi) {
    sorted = vulnerabilities.slice().sort(function(a, b) {
      return ((a.ai_analysis && a.ai_analysis.priority_rank) || 99) - ((b.ai_analysis && b.ai_analysis.priority_rank) || 99);
    });
  } else {
    sorted = vulnerabilities.slice().sort(function(a, b) { return b.cvss_score - a.cvss_score; });
  }

  var displayed = sorted.slice(0, 15);

  for (var idx = 0; idx < displayed.length; idx++) {
    var v = displayed[idx];
    checkPageSpace(doc, 90);
    if (idx > 0) { hr(doc); doc.moveDown(0.2); }

    var rank = isAi ? ((v.ai_analysis && v.ai_analysis.priority_rank) || idx + 1) : idx + 1;
    var score = isAi ? ((v.ai_analysis && v.ai_analysis.ai_risk_score) || v.cvss_score) : v.cvss_score;
    var sevColor = SEVERITY_COLORS[v.severity] || COLORS.info;

    // Finding header with severity accent
    var headerY = doc.y;
    doc.save().rect(PAGE_MARGIN, headerY, 3, 16).fill(sevColor).restore();

    doc.font("Helvetica-Bold").fontSize(10.5).fillColor(COLORS.navy)
       .text("#" + rank + "  " + v.title, PAGE_MARGIN + 10, headerY + 1);

    doc.moveDown(0.2);

    // Metadata line
    doc.font("Helvetica-Bold").fontSize(8).fillColor(sevColor)
       .text((v.severity || "").toUpperCase(), PAGE_MARGIN + 10, doc.y, { continued: true });
    doc.font("Helvetica").fillColor(COLORS.slate400)
       .text("   |   Score: " + score.toFixed(1) + "   |   Asset: " + (v.affected_asset || "N/A") + "   |   Source: " + (v.source || "N/A") + "   |   Confidence: " + (v.confidence || "N/A"));

    doc.moveDown(0.2);

    // Description
    if (v.description) {
      doc.font("Helvetica").fontSize(9).fillColor(COLORS.slate600)
         .text(truncate(v.description, 450), PAGE_MARGIN + 10, doc.y, {
           width: CONTENT_WIDTH - 14, align: "justify", lineGap: 1.5,
         });
    }

    // AI enrichment block
    if (isAi && v.ai_analysis) {
      doc.moveDown(0.2);
      var aiY = doc.y;

      var remediation = v.ai_analysis.remediation || "";
      var impact = v.ai_analysis.business_impact || "N/A";
      var exploit = v.ai_analysis.exploitability_score ? v.ai_analysis.exploitability_score.toFixed(1) : "N/A";
      var fpProb = v.ai_analysis.false_positive_probability || 0;

      doc.font("Helvetica-Bold").fontSize(8).fillColor(COLORS.accent)
         .text("AI ANALYSIS", PAGE_MARGIN + 14, aiY + 2);
      doc.font("Helvetica").fontSize(8).fillColor(COLORS.slate600)
         .text("Exploitability: " + exploit + "/10   |   Business Impact: " + impact + "   |   FP Probability: " + (fpProb * 100).toFixed(0) + "%", PAGE_MARGIN + 14, doc.y + 1);

      if (remediation) {
        doc.moveDown(0.15);
        doc.font("Helvetica-Oblique").fontSize(8).fillColor(COLORS.slate600)
           .text("Remediation: " + truncate(remediation, 350), PAGE_MARGIN + 14, doc.y, {
             width: CONTENT_WIDTH - 28, lineGap: 1,
           });
      }

      if (fpProb > 0.3) {
        doc.moveDown(0.1);
        doc.font("Helvetica-Bold").fontSize(8).fillColor(COLORS.medium)
           .text("! Possible False Positive (" + (fpProb * 100).toFixed(0) + "%): " + truncate(v.ai_analysis.false_positive_reason || "", 200), PAGE_MARGIN + 14, doc.y, { width: CONTENT_WIDTH - 28 });
      }

      // Draw border around AI block
      var blockH = doc.y - aiY + 8;
      doc.save()
         .roundedRect(PAGE_MARGIN + 10, aiY - 2, CONTENT_WIDTH - 14, blockH, 3)
         .lineWidth(0.5).strokeColor(COLORS.blue100).stroke()
         .restore();

      doc.y = aiY + blockH + 2;
    }

    doc.moveDown(0.2);
  }

  if (sorted.length > 15) {
    doc.moveDown(0.3);
    body(doc, "... and " + (sorted.length - 15) + " additional finding(s). See Appendix for the complete list.");
  }
}

// ---------------------------------------------------------------------------
// 7. Comparison
// ---------------------------------------------------------------------------
function addComparison(doc, metrics, pageCounter) {
  sectionPage(doc, "07  Risk Comparison: Traditional vs AI", pageCounter);

  if (!metrics) {
    body(doc, "No comparison metrics available.");
    return;
  }

  subHeading(doc, "Statistical Summary");

  kv(doc, "Total Vulnerabilities Analysed", metrics.total_vulnerabilities);
  kv(doc, "Kendall's Tau (Rank Correlation)", (metrics.kendall_tau != null ? metrics.kendall_tau.toFixed(3) : "N/A") + " -- " + (metrics.kendall_tau_interpretation || ""));
  kv(doc, "Divergent Rankings", (metrics.divergent_rankings_count || 0) + " (" + (metrics.divergent_rankings_percent || 0).toFixed(1) + "%)");
  kv(doc, "False Positives Detected (AI)", metrics.false_positives_detected_count);
  kv(doc, "Probable False Positives", metrics.false_positives_probable_count);
  kv(doc, "Traditional Estimated Time", Math.round((metrics.traditional_estimated_time_seconds || 0) / 60) + " min");
  kv(doc, "AI Processing Time", (metrics.ai_processing_time_seconds || 0).toFixed(1) + "s");
  kv(doc, "Time Saved", Math.round((metrics.time_saved_seconds || 0) / 60) + " min (" + (metrics.time_saved_percent || 0).toFixed(1) + "%)");
  kv(doc, "Average CVSS Score", (metrics.avg_cvss_score || 0).toFixed(2));
  kv(doc, "Average AI Risk Score", (metrics.avg_ai_risk_score || 0).toFixed(2));

  doc.moveDown(0.5);
  subHeading(doc, "Ranking Comparison Table (Top 15)");

  var ranking = (metrics.ranking_comparison || []).slice(0, 15);
  var rows = [];
  for (var i = 0; i < ranking.length; i++) {
    var r = ranking[i];
    var change;
    if (r.rank_change > 0) { change = "^ " + r.rank_change; }
    else if (r.rank_change < 0) { change = "v " + Math.abs(r.rank_change); }
    else { change = "--"; }
    rows.push([
      truncate(r.title, 38),
      String(r.traditional_rank),
      String(r.ai_rank),
      change,
      (r.cvss_score || 0).toFixed(1),
      (r.ai_risk_score || 0).toFixed(1),
    ]);
  }

  drawTable(doc,
    ["Finding", "CVSS Rank", "AI Rank", "Change", "CVSS", "AI Score"],
    rows,
    [185, 52, 48, 48, 42, 52],
    {
      cellColor: function(row, col) {
        if (col === 3 && rows[row]) {
          var ch = rows[row][3];
          if (ch && ch.indexOf("^") >= 0) return COLORS.low;
          if (ch && ch.indexOf("v") >= 0) return COLORS.high;
        }
        return null;
      }
    }
  );
}

// ---------------------------------------------------------------------------
// 8. Recommendations
// ---------------------------------------------------------------------------
function addRecommendations(doc, vulnerabilities, pageCounter) {
  sectionPage(doc, "08  Recommendations", pageCounter);

  body(doc, "The following remediation actions are recommended, ordered by AI-assisted priority ranking:");

  var highPriority = vulnerabilities
    .filter(function(v) { return v.ai_analysis && v.ai_analysis.priority_rank; })
    .sort(function(a, b) { return a.ai_analysis.priority_rank - b.ai_analysis.priority_rank; })
    .slice(0, 10);

  if (highPriority.length === 0) {
    body(doc, "No AI-enriched recommendations available. Refer to vendor advisories and security best practices for each identified finding.");
    return;
  }

  for (var i = 0; i < highPriority.length; i++) {
    var v = highPriority[i];
    checkPageSpace(doc, 50);
    var sevColor = SEVERITY_COLORS[v.severity] || COLORS.info;

    doc.font("Helvetica-Bold").fontSize(10).fillColor(COLORS.darkSlate)
       .text((i + 1) + ". " + v.title, PAGE_MARGIN);

    doc.font("Helvetica-Bold").fontSize(8).fillColor(sevColor)
       .text((v.severity || "").toUpperCase() + "  |  CVSS: " + (v.cvss_score || 0).toFixed(1) + "  |  AI Score: " + ((v.ai_analysis && v.ai_analysis.ai_risk_score) || 0).toFixed(1), PAGE_MARGIN + 10, doc.y);

    doc.moveDown(0.15);
    body(doc, (v.ai_analysis && v.ai_analysis.remediation) || "Refer to vendor advisories and security best practices.");
    doc.moveDown(0.1);
  }
}

// ---------------------------------------------------------------------------
// 9. Conclusion
// ---------------------------------------------------------------------------
function addConclusion(doc, metrics, pageCounter) {
  sectionPage(doc, "09  Conclusion", pageCounter);

  body(doc,
    "This assessment demonstrates the value of combining traditional penetration testing techniques " +
    "with AI-assisted analysis. While CVSS-based scoring provides a standardised severity baseline, " +
    "the AI analysis layer adds contextual depth -- including exploitability assessment, business impact " +
    "evaluation, and false positive detection -- that enables more effective vulnerability prioritisation."
  );

  body(doc,
    "With a Kendall's Tau of " + ((metrics && metrics.kendall_tau) || 0).toFixed(3) + ", the AI ranking diverged meaningfully " +
    "from the traditional CVSS ordering, highlighting " + ((metrics && metrics.divergent_rankings_count) || 0) + " ranking " +
    "differences. This demonstrates that numeric severity scores alone are insufficient to capture " +
    "real-world exploitability and business risk."
  );

  body(doc,
    "The AI module identified probable false positives that would otherwise consume analyst time during " +
    "remediation planning. This automated triage capability represents a significant efficiency gain " +
    "for security operations teams dealing with high-volume vulnerability data."
  );

  subHeading(doc, "Future Work");
  body(doc,
    "Recommended next steps include: authenticated web application testing, integration with SIEM " +
    "and ticketing platforms, longitudinal vulnerability trending across multiple scan cycles, and " +
    "expansion of the ML exploitability classifier training dataset."
  );

  subHeading(doc, "Ethical & Legal Considerations");
  body(doc,
    "This assessment was conducted under formal written authorisation. All scanning activities were " +
    "performed in accordance with applicable laws. AI-generated analysis was programmatically " +
    "validated before inclusion in this report. No data was transmitted to third parties beyond " +
    "the OpenAI API calls required for vulnerability analysis."
  );
}

// ---------------------------------------------------------------------------
// 10. Appendix
// ---------------------------------------------------------------------------
function addAppendix(doc, vulnerabilities, nmapRaw, zapRaw, pageCounter) {
  sectionPage(doc, "10  Appendix", pageCounter);

  subHeading(doc, "A. Complete Vulnerability List");

  var rows = [];
  for (var i = 0; i < vulnerabilities.length; i++) {
    var v = vulnerabilities[i];
    rows.push([
      String(i + 1),
      truncate(v.title, 42),
      (v.severity || "").toUpperCase(),
      (v.cvss_score || 0).toFixed(1),
      (v.ai_analysis && v.ai_analysis.ai_risk_score) ? v.ai_analysis.ai_risk_score.toFixed(1) : "--",
      truncate(v.affected_asset, 28),
    ]);
  }

  drawTable(doc,
    ["#", "Title", "Severity", "CVSS", "AI", "Asset"],
    rows,
    [24, 200, 60, 40, 36, CONTENT_WIDTH - 360],
    {
      cellColor: function(row, col) {
        if (col === 2 && vulnerabilities[row]) {
          return SEVERITY_COLORS[(vulnerabilities[row].severity || "").toLowerCase()] || null;
        }
        return null;
      },
    }
  );

  checkPageSpace(doc, 120);
  doc.moveDown(0.5);
  subHeading(doc, "B. Scan Metadata");

  if (nmapRaw) {
    kv(doc, "Nmap Scan ID", nmapRaw.scan_id);
    kv(doc, "Nmap Target", nmapRaw.target);
    kv(doc, "Nmap Ports Scanned", nmapRaw.ports_scanned);
    kv(doc, "Nmap Execution Time", (nmapRaw.execution_time_seconds || 0).toFixed(1) + "s");
    kv(doc, "Hosts Discovered", nmapRaw.hosts_scanned || (nmapRaw.hosts || []).length);
    doc.moveDown(0.3);
  }
  if (zapRaw) {
    kv(doc, "ZAP Scan ID", zapRaw.scan_id);
    kv(doc, "ZAP Target", zapRaw.target);
    kv(doc, "ZAP Execution Time", (zapRaw.execution_time_seconds || 0).toFixed(1) + "s");
    kv(doc, "ZAP Total Alerts", zapRaw.total_alerts);
    kv(doc, "ZAP Unique Vulnerabilities", zapRaw.unique_vulnerabilities);
  }

  checkPageSpace(doc, 60);
  doc.moveDown(0.5);
  subHeading(doc, "C. Report Generation");
  kv(doc, "Generated At", new Date().toISOString());
  kv(doc, "Generator", "AI-Assisted Pentesting Platform v1.0");
  kv(doc, "AI Model", "GPT-4o (OpenAI)");
  kv(doc, "Report Engine", "PDFKit (Node.js)");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function generateReport(vulnerabilities, metrics, nmapRaw, zapRaw) {
  var reportsDir = config.paths.reportsDir;
  ensureDir(reportsDir);

  var timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  var outputPath = path.join(reportsDir, "pentest_report_" + timestamp + ".pdf");

  var target = (nmapRaw && nmapRaw.target) || (zapRaw && zapRaw.target) || "Multiple targets";
  var meta = { target: target, timestamp: new Date().toISOString() };

  logger.info("Generating PDF report to %s...", outputPath);

  return new Promise(function(resolve, reject) {
    var doc = new PDFDocument({
      size: "A4",
      margins: { top: PAGE_MARGIN, bottom: PAGE_MARGIN, left: PAGE_MARGIN, right: PAGE_MARGIN },
      bufferPages: true,
      info: {
        Title: "Security Assessment Report - " + target,
        Author: "AI-Assisted Pentesting System",
        Subject: "Penetration Testing Report",
        Keywords: "penetration testing, security assessment, AI, CVSS",
      },
    });

    var stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    var pageCounter = { n: 1 };

    try {
      addCoverPage(doc, meta);
      addToc(doc, pageCounter);
      addExecutiveSummary(doc, vulnerabilities, metrics, pageCounter);
      addScope(doc, meta, pageCounter);
      addMethodology(doc, pageCounter);
      addTools(doc, pageCounter);
      addFindings(doc, vulnerabilities, false, pageCounter);
      addFindings(doc, vulnerabilities, true, pageCounter);
      addComparison(doc, metrics, pageCounter);
      addRecommendations(doc, vulnerabilities, pageCounter);
      addConclusion(doc, metrics, pageCounter);
      addAppendix(doc, vulnerabilities, nmapRaw, zapRaw, pageCounter);
    } catch (err) {
      doc.end();
      return reject(err);
    }

    doc.end();
    stream.on("finish", function() {
      var size = fs.statSync(outputPath).size;
      logger.info("Report generated: %s (%d bytes, %d pages)", outputPath, size, pageCounter.n);
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
  var files = fs.readdirSync(dir)
    .filter(function(f) { return f.startsWith(prefix) && f.endsWith(".json"); })
    .sort().reverse();
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------
async function main() {
  var aiData = readLatestFile(config.paths.processedDir, "ai_analysis_");
  var metricsData = readLatestFile(config.paths.processedDir, "metrics");
  var nmapRaw = readLatestFile(config.paths.nmapDir, "nmap_");
  var zapRaw = readLatestFile(config.paths.zapDir, "zap_");

  if (!aiData) {
    logger.error("No AI analysis data found. Run ai_analyzer.js first.");
    process.exit(1);
  }

  var outPath = await generateReport(aiData.vulnerabilities, metricsData, nmapRaw, zapRaw);
  console.log("Report saved: " + outPath);
}

if (require.main === module) {
  main().catch(function(err) {
    logger.error("Report generation failed:", err);
    process.exit(1);
  });
}

module.exports = { generateReport };
