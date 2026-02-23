/**
 * types/index.ts
 *
 * Central TypeScript type definitions for the AI-Assisted Pentesting Dashboard.
 * All types mirror the JSON shapes produced by the backend modules.
 */

// ---------------------------------------------------------------------------
// Vulnerability (unified format from normalizer.js)
// ---------------------------------------------------------------------------
export interface AiAnalysis {
  priority_rank: number;
  exploitability_score: number;
  business_impact: string;
  remediation: string;
  false_positive_probability: number;
  false_positive_reason: string;
  severity_justification: string;
  ai_risk_score: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Source = "nmap" | "owasp_zap";
export type Confidence = "high" | "medium" | "low";

export interface Vulnerability {
  id: string;
  source: Source;
  title: string;
  severity: Severity;
  cvss_score: number;
  description: string;
  affected_asset: string;
  confidence: Confidence;
  references: string[];
  /** Present after AI analysis step */
  ai_analysis?: AiAnalysis;
  /** Present after ML classification step */
  ml_exploitability_score?: number;
  ml_exploitable?: boolean;
}

// ---------------------------------------------------------------------------
// Metrics (from comparison_engine.js metrics.json)
// ---------------------------------------------------------------------------
export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface RankingEntry {
  id: string;
  title: string;
  traditional_rank: number;
  ai_rank: number;
  rank_change: number;
  cvss_score: number;
  ai_risk_score: number;
  false_positive_prob: number;
}

export interface Metrics {
  generated_at: string;
  total_vulnerabilities: number;
  kendall_tau: number;
  kendall_tau_interpretation: string;
  divergent_rankings_count: number;
  divergent_rankings_percent: number;
  false_positives_detected_count: number;
  false_positives_probable_count: number;
  false_positive_ids: string[];
  traditional_estimated_time_seconds: number;
  ai_processing_time_seconds: number;
  time_saved_seconds: number;
  time_saved_percent: number;
  manual_time_per_vuln_assumption_seconds: number;
  avg_cvss_score: number;
  avg_ai_risk_score: number;
  ai_tokens_used: number;
  ai_model: string;
  severity_distribution: SeverityDistribution;
  ranking_comparison: RankingEntry[];
}

// ---------------------------------------------------------------------------
// Scan status
// ---------------------------------------------------------------------------
export type ScanState =
  | "idle"
  | "scanning"
  | "normalizing"
  | "analyzing"
  | "comparing"
  | "reporting"
  | "complete"
  | "error";

export interface ScanStatus {
  state: ScanState;
  target: string;
  message: string;
  startedAt?: string;
  completedAt?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
export interface Report {
  report_path: string;
  message: string;
  generated_at?: string;
}

// ---------------------------------------------------------------------------
// API response envelopes
// ---------------------------------------------------------------------------
export interface VulnerabilitiesResponse {
  generated_at: string;
  total_vulnerabilities: number;
  vulnerabilities: Vulnerability[];
}

export interface PipelineResponse {
  status: string;
  vulnerabilities_found: number;
  report_path: string;
  metrics: Metrics;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  version: string;
}

// ---------------------------------------------------------------------------
// Scan history (returned by GET /api/scans and GET /api/scans/:id)
// ---------------------------------------------------------------------------

/** Severity counts bundled with each scan summary row */
export interface ScanSeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

/** One row in the scan history table (GET /api/scans) */
export interface ScanSummary {
  id: string;
  target: string;
  /** ISO 8601 timestamp when the scan started */
  timestamp: string;
  /** Wall-clock duration in seconds */
  duration: number;
  /** Total number of vulnerabilities found */
  vulnerability_count: number;
  status: "complete" | "running" | "error";
  severity_summary: ScanSeveritySummary;
}

/** Full scan detail (GET /api/scans/:id) */
export interface ScanDetail extends ScanSummary {
  vulnerabilities: Vulnerability[];
  metrics: Metrics | null;
  report_path: string | null;
}
