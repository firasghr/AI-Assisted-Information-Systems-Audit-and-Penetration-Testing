/**
 * test_comparison.js - Tests for the comparison engine.
 */

"use strict";

const { compare, rankByTraditional, kendallTau } = require("../src/comparison/comparison_engine");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeVuln(id, severity, cvssScore, aiPriorityRank, aiRiskScore) {
  return {
    id,
    title: `Vulnerability ${id}`,
    severity,
    cvss_score: cvssScore,
    affected_asset: "192.168.1.1",
    source: "nmap",
    description: "Test vulnerability.",
    confidence: "high",
    references: [],
    ai_analysis: {
      priority_rank: aiPriorityRank,
      exploitability_score: cvssScore * 0.9,
      business_impact: "High business impact.",
      remediation: "Apply patch.",
      false_positive_probability: 0.05,
      false_positive_reason: "",
      severity_justification: "Justified.",
      ai_risk_score: aiRiskScore,
    },
  };
}

const sampleVulnerabilities = [
  makeVuln("v1", "high",   7.5, 1, 8.0),
  makeVuln("v2", "medium", 5.0, 3, 4.5),
  makeVuln("v3", "critical", 9.5, 2, 9.0),
  makeVuln("v4", "low",    2.5, 5, 2.0),
  makeVuln("v5", "medium", 5.5, 4, 5.0),
];

const sampleAiMetrics = {
  total_tokens: 1500,
  processing_time_ms: 2000,
  vulnerabilities_analysed: 5,
  model: "gpt-4o",
};

// ---------------------------------------------------------------------------
// Tests: kendallTau
// ---------------------------------------------------------------------------

describe("kendallTau", () => {
  test("returns 1.0 for identical rankings", () => {
    const ranks = [1, 2, 3, 4, 5];
    expect(kendallTau(ranks, ranks)).toBeCloseTo(1.0, 4);
  });

  test("returns -1.0 for perfectly reversed rankings", () => {
    const r1 = [1, 2, 3, 4, 5];
    const r2 = [5, 4, 3, 2, 1];
    expect(kendallTau(r1, r2)).toBeCloseTo(-1.0, 4);
  });

  test("returns value between -1 and 1", () => {
    const r1 = [1, 3, 2, 5, 4];
    const r2 = [2, 1, 3, 4, 5];
    const tau = kendallTau(r1, r2);
    expect(tau).toBeGreaterThanOrEqual(-1);
    expect(tau).toBeLessThanOrEqual(1);
  });

  test("returns 1 for single element", () => {
    expect(kendallTau([1], [1])).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: rankByTraditional
// ---------------------------------------------------------------------------

describe("rankByTraditional", () => {
  test("assigns rank 1 to highest CVSS score", () => {
    const ranked = rankByTraditional(sampleVulnerabilities);
    const rank1 = ranked.find((v) => v.traditional_rank === 1);
    expect(rank1).toBeDefined();
    expect(rank1.cvss_score).toBe(9.5);
  });

  test("all vulnerabilities have a traditional_rank", () => {
    const ranked = rankByTraditional(sampleVulnerabilities);
    ranked.forEach((v) => {
      expect(v).toHaveProperty("traditional_rank");
      expect(typeof v.traditional_rank).toBe("number");
    });
  });

  test("ranks are unique integers from 1 to n", () => {
    const ranked = rankByTraditional(sampleVulnerabilities);
    const ranks = ranked.map((v) => v.traditional_rank).sort((a, b) => a - b);
    for (let i = 0; i < ranks.length; i++) {
      expect(ranks[i]).toBe(i + 1);
    }
  });

  test("does not mutate the original array", () => {
    const original = sampleVulnerabilities.map((v) => ({ ...v }));
    rankByTraditional(sampleVulnerabilities);
    sampleVulnerabilities.forEach((v, i) => {
      expect(v.id).toBe(original[i].id);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: compare
// ---------------------------------------------------------------------------

describe("compare", () => {
  test("returns required metric fields", () => {
    const metrics = compare(sampleVulnerabilities, sampleAiMetrics);
    const required = [
      "total_vulnerabilities",
      "kendall_tau",
      "kendall_tau_interpretation",
      "divergent_rankings_count",
      "false_positives_detected_count",
      "time_saved_seconds",
      "time_saved_percent",
      "avg_cvss_score",
      "avg_ai_risk_score",
      "ai_tokens_used",
      "ranking_comparison",
    ];
    required.forEach((key) => {
      expect(metrics).toHaveProperty(key);
    });
  });

  test("total_vulnerabilities matches input", () => {
    const metrics = compare(sampleVulnerabilities, sampleAiMetrics);
    expect(metrics.total_vulnerabilities).toBe(sampleVulnerabilities.length);
  });

  test("kendall_tau is between -1 and 1", () => {
    const metrics = compare(sampleVulnerabilities, sampleAiMetrics);
    expect(metrics.kendall_tau).toBeGreaterThanOrEqual(-1);
    expect(metrics.kendall_tau).toBeLessThanOrEqual(1);
  });

  test("detects false positives correctly", () => {
    const vulnsWithFP = [
      ...sampleVulnerabilities,
      makeVuln("fp1", "medium", 5.0, 6, 4.0),
    ];
    // Override the last vuln's FP probability
    vulnsWithFP[vulnsWithFP.length - 1].ai_analysis.false_positive_probability = 0.9;
    vulnsWithFP[vulnsWithFP.length - 1].ai_analysis.false_positive_reason = "Likely scanner artefact.";

    const metrics = compare(vulnsWithFP, sampleAiMetrics);
    expect(metrics.false_positives_detected_count).toBe(1);
  });

  test("time_saved is positive when AI is faster than manual", () => {
    const metrics = compare(sampleVulnerabilities, sampleAiMetrics, 120);
    // 5 vulns * 120s = 600s manual; AI = 2s → saved ~598s
    expect(metrics.time_saved_seconds).toBeGreaterThan(0);
  });

  test("ranking_comparison has correct structure", () => {
    const metrics = compare(sampleVulnerabilities, sampleAiMetrics);
    metrics.ranking_comparison.forEach((entry) => {
      expect(entry).toHaveProperty("id");
      expect(entry).toHaveProperty("traditional_rank");
      expect(entry).toHaveProperty("ai_rank");
      expect(entry).toHaveProperty("rank_change");
    });
  });

  test("handles empty vulnerabilities gracefully", () => {
    const metrics = compare([], {});
    expect(metrics.total_vulnerabilities).toBe(0);
    expect(metrics.kendall_tau).toBe(1);
  });
});
