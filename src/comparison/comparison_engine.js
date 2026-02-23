/**
 * comparison_engine.js - Traditional vs AI-assisted analysis comparison.
 *
 * Statistical Reasoning:
 *   This module quantifies the added value of AI-assisted vulnerability
 *   analysis over traditional CVSS-based prioritisation.
 *
 *   Traditional approach:
 *     - Rank vulnerabilities by CVSS score (descending)
 *     - Higher CVSS = higher priority (linear, context-free)
 *     - Time: proportional to finding count × analyst review time
 *
 *   AI-assisted approach:
 *     - LLM produces a priority_rank for each finding
 *     - Considers exploitability, business impact, and context
 *     - Detects probable false positives
 *     - Time: LLM API call latency (typically seconds)
 *
 *   Metrics collected:
 *     - Kendall's τ (tau): Rank correlation between CVSS ranking and AI ranking.
 *       A low τ indicates the AI reordered findings significantly — i.e., CVSS
 *       alone is insufficient for prioritisation.
 *     - False positive detection: Count of findings the AI flagged as likely FP.
 *     - Time comparison: Traditional processing time (estimated) vs AI time.
 *     - Prioritisation divergence: Percentage of findings whose rank changed
 *       by more than one position.
 *
 * Output:
 *   Saves metrics.json to data/processed/ for use in the report generator.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const logger = require("../utils/logger");
const config = require("../utils/config");

// ---------------------------------------------------------------------------
// Traditional CVSS-based ranking
// ---------------------------------------------------------------------------

/**
 * Assign a traditional CVSS-based priority rank to each vulnerability.
 * Ties are broken by source (nmap after zap) then alphabetically by title.
 *
 * @param {Array} vulnerabilities - Normalised vulnerability array.
 * @returns {Array} Copy of array with added `traditional_rank` field.
 */
function rankByTraditional(vulnerabilities) {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

  const sorted = [...vulnerabilities].sort((a, b) => {
    // Primary sort: CVSS score descending
    const cvdiff = b.cvss_score - a.cvss_score;
    if (cvdiff !== 0) return cvdiff;
    // Secondary: severity band
    const sevDiff =
      (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    if (sevDiff !== 0) return sevDiff;
    // Tertiary: alphabetical by title
    return a.title.localeCompare(b.title);
  });

  return sorted.map((v, i) => ({ ...v, traditional_rank: i + 1 }));
}

// ---------------------------------------------------------------------------
// Kendall's τ (tau-b) rank correlation
// ---------------------------------------------------------------------------

/**
 * Compute Kendall's τ-b between two ranking arrays.
 * τ ∈ [-1, 1]: 1 = identical order, -1 = reversed, 0 = no correlation.
 *
 * @param {number[]} ranks1 - First ranking array.
 * @param {number[]} ranks2 - Second ranking array.
 * @returns {number} Kendall's τ-b coefficient.
 */
function kendallTau(ranks1, ranks2) {
  const n = ranks1.length;
  if (n < 2) return 1;

  let concordant = 0;
  let discordant = 0;
  let ties1 = 0;
  let ties2 = 0;

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const a = Math.sign(ranks1[i] - ranks1[j]);
      const b = Math.sign(ranks2[i] - ranks2[j]);
      const product = a * b;
      if (product > 0) concordant++;
      else if (product < 0) discordant++;
      if (a === 0) ties1++;
      if (b === 0) ties2++;
    }
  }

  const n0 = (n * (n - 1)) / 2;
  const denominator = Math.sqrt((n0 - ties1) * (n0 - ties2));
  if (denominator === 0) return 1;

  return (concordant - discordant) / denominator;
}

// ---------------------------------------------------------------------------
// Main comparison function
// ---------------------------------------------------------------------------

/**
 * Compare traditional CVSS-based prioritisation with AI-assisted results.
 *
 * @param {Array} aiAnalysisData - Output from ai_analyzer.js (enriched vuln array).
 * @param {Object} aiMetrics - Timing/token metrics from AI analysis.
 * @param {number} [manualTimePerVulnSeconds=120] - Estimated seconds a human
 *   analyst spends reviewing each finding manually (default: 2 minutes).
 * @returns {Object} Comparison metrics and statistics.
 */
function compare(aiAnalysisData, aiMetrics, manualTimePerVulnSeconds = 120) {
  const vulnerabilities = aiAnalysisData;
  const n = vulnerabilities.length;

  logger.info("Running comparison for %d vulnerabilities...", n);

  // 1. Traditional ranking
  const traditionalRanked = rankByTraditional(vulnerabilities);

  // Build lookup: id -> traditional_rank
  const tradRankMap = new Map(traditionalRanked.map((v) => [v.id, v.traditional_rank]));

  // 2. AI ranking (from ai_analysis.priority_rank)
  // Re-assign sequential AI ranks in case of ties/gaps
  const aiRanked = [...vulnerabilities]
    .sort((a, b) => (a.ai_analysis?.priority_rank || 99) - (b.ai_analysis?.priority_rank || 99))
    .map((v, i) => ({ ...v, ai_rank: i + 1 }));

  const aiRankMap = new Map(aiRanked.map((v) => [v.id, v.ai_rank]));

  // 3. Compute rank vectors (aligned by ID order)
  const ids = vulnerabilities.map((v) => v.id);
  const tradRanks = ids.map((id) => tradRankMap.get(id) || n);
  const aiRanks = ids.map((id) => aiRankMap.get(id) || n);

  // 4. Kendall's τ
  const tau = kendallTau(tradRanks, aiRanks);

  // 5. Rank divergence: % of findings that moved > 1 position
  const divergentCount = ids.filter(
    (id) => Math.abs((tradRankMap.get(id) || n) - (aiRankMap.get(id) || n)) > 1
  ).length;
  const divergencePercent = n > 0 ? ((divergentCount / n) * 100).toFixed(1) : "0.0";

  // 6. False positive detection
  const fpDetected = vulnerabilities.filter(
    (v) => (v.ai_analysis?.false_positive_probability || 0) > 0.5
  );
  const fpProbable = vulnerabilities.filter(
    (v) =>
      (v.ai_analysis?.false_positive_probability || 0) > 0.3 &&
      (v.ai_analysis?.false_positive_probability || 0) <= 0.5
  );

  // 7. Time comparison
  const estimatedManualTimeSeconds = n * manualTimePerVulnSeconds;
  const aiTimeSeconds = (aiMetrics?.processing_time_ms || 0) / 1000;
  const timeSavedSeconds = estimatedManualTimeSeconds - aiTimeSeconds;
  const timeSavedPercent =
    estimatedManualTimeSeconds > 0
      ? ((timeSavedSeconds / estimatedManualTimeSeconds) * 100).toFixed(1)
      : "0.0";

  // 8. Average AI risk score vs average CVSS score
  const avgCvss =
    n > 0
      ? (vulnerabilities.reduce((s, v) => s + v.cvss_score, 0) / n).toFixed(2)
      : 0;
  const avgAiRisk =
    n > 0
      ? (
          vulnerabilities.reduce((s, v) => s + (v.ai_analysis?.ai_risk_score || 0), 0) /
          n
        ).toFixed(2)
      : 0;

  // 9. Severity distribution comparison
  const severities = ["critical", "high", "medium", "low", "informational"];
  const severityDist = {};
  for (const sev of severities) {
    severityDist[sev] = vulnerabilities.filter((v) => v.severity === sev).length;
  }

  const metrics = {
    generated_at: new Date().toISOString(),
    total_vulnerabilities: n,

    // Ranking comparison
    kendall_tau: parseFloat(tau.toFixed(4)),
    kendall_tau_interpretation:
      tau >= 0.8
        ? "High agreement: AI mostly agrees with CVSS ranking"
        : tau >= 0.5
        ? "Moderate agreement: AI reordered findings notably"
        : "Low agreement: AI significantly reprioritised findings",
    divergent_rankings_count: divergentCount,
    divergent_rankings_percent: parseFloat(divergencePercent),

    // False positive detection
    false_positives_detected_count: fpDetected.length,
    false_positives_probable_count: fpProbable.length,
    false_positive_ids: fpDetected.map((v) => v.id),

    // Time metrics
    traditional_estimated_time_seconds: estimatedManualTimeSeconds,
    ai_processing_time_seconds: parseFloat(aiTimeSeconds.toFixed(2)),
    time_saved_seconds: parseFloat(timeSavedSeconds.toFixed(2)),
    time_saved_percent: parseFloat(timeSavedPercent),
    manual_time_per_vuln_assumption_seconds: manualTimePerVulnSeconds,

    // Score comparison
    avg_cvss_score: parseFloat(avgCvss),
    avg_ai_risk_score: parseFloat(avgAiRisk),

    // AI token usage
    ai_tokens_used: aiMetrics?.total_tokens || 0,
    ai_model: aiMetrics?.model || "unknown",

    // Severity distribution
    severity_distribution: severityDist,

    // Ranked comparison table (first 20 for report)
    ranking_comparison: ids.slice(0, 20).map((id) => {
      const v = vulnerabilities.find((x) => x.id === id);
      return {
        id,
        title: v?.title || "",
        traditional_rank: tradRankMap.get(id) || n,
        ai_rank: aiRankMap.get(id) || n,
        rank_change: (tradRankMap.get(id) || n) - (aiRankMap.get(id) || n),
        cvss_score: v?.cvss_score || 0,
        ai_risk_score: v?.ai_analysis?.ai_risk_score || 0,
        false_positive_prob: v?.ai_analysis?.false_positive_probability || 0,
      };
    }),
  };

  logger.info(
    "Comparison complete | tau=%.4f divergence=%s%% fp_detected=%d time_saved=%ds",
    metrics.kendall_tau,
    metrics.divergent_rankings_percent,
    metrics.false_positives_detected_count,
    metrics.time_saved_seconds
  );

  return metrics;
}

// ---------------------------------------------------------------------------
// Read latest AI analysis data
// ---------------------------------------------------------------------------
function readLatestAiAnalysis() {
  const dir = config.paths.processedDir;
  if (!fs.existsSync(dir)) return null;
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.startsWith("ai_analysis_") && f.endsWith(".json"))
    .sort()
    .reverse();
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------
async function main() {
  const data = readLatestAiAnalysis();
  if (!data) {
    logger.error("No AI analysis data found. Run ai_analyzer.js first.");
    process.exit(1);
  }

  const metrics = compare(data.vulnerabilities, data.metrics);

  if (!fs.existsSync(config.paths.processedDir)) {
    fs.mkdirSync(config.paths.processedDir, { recursive: true });
  }

  const outFile = path.join(config.paths.processedDir, "metrics.json");
  fs.writeFileSync(outFile, JSON.stringify(metrics, null, 2));
  logger.info("Comparison metrics saved to %s", outFile);
  console.log(JSON.stringify(metrics, null, 2));

  return metrics;
}

if (require.main === module) {
  main().catch((err) => {
    logger.error("Comparison engine failed:", err);
    process.exit(1);
  });
}

module.exports = { compare, rankByTraditional, kendallTau };
