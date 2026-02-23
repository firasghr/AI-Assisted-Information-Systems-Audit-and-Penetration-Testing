/**
 * app/history/[id]/page.tsx
 *
 * Scan detail page — shows the full results of a single past scan including:
 *   - Scan metadata (target, timestamps, duration, status)
 *   - Key metrics cards (total vulns, critical count, Kendall τ, time saved)
 *   - Full vulnerability table (title, severity, CVSS, AI score, source, asset)
 *   - Link to download the PDF report if available
 *
 * Fetches from GET /api/scans/:id via the API service layer.
 */

"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Download,
  AlertCircle,
  ShieldCheck,
  Clock,
  Activity,
  Target,
} from "lucide-react";
import type { ScanDetail, Vulnerability } from "@/types";
import { getScanById, BASE_URL } from "@/services/api";
import SeveritySummaryBadges from "@/components/history/SeveritySummaryBadges";

// ---------------------------------------------------------------------------
// Severity badge helper
// ---------------------------------------------------------------------------
const SEV_STYLES: Record<string, string> = {
  critical:      "bg-red-100 text-red-700 ring-red-200",
  high:          "bg-orange-100 text-orange-700 ring-orange-200",
  medium:        "bg-yellow-100 text-yellow-700 ring-yellow-200",
  low:           "bg-green-100 text-green-700 ring-green-200",
  informational: "bg-slate-100 text-slate-600 ring-slate-200",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 capitalize ${
        SEV_STYLES[severity] ?? "bg-slate-100 text-slate-600"
      }`}
    >
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Metric card
// ---------------------------------------------------------------------------
function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  className = "",
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ElementType;
  className?: string;
}) {
  return (
    <div className={`rounded-xl border border-slate-200 bg-white p-4 shadow-sm ${className}`}>
      <div className="mb-2 flex items-center gap-2 text-slate-500">
        <Icon className="h-4 w-4" />
        <span className="text-xs font-semibold uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-2xl font-bold text-slate-900">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-slate-400">{sub}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Vulnerability table
// ---------------------------------------------------------------------------
function VulnerabilityTable({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  if (vulnerabilities.length === 0) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-slate-400 shadow-sm">
        No vulnerabilities recorded for this scan.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">#</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">CVSS</th>
              <th className="px-4 py-3">AI Score</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Affected Asset</th>
              <th className="px-4 py-3">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {vulnerabilities.map((v, i) => (
              <tr key={v.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-4 py-3 text-slate-400">{i + 1}</td>
                <td className="px-4 py-3 font-medium text-slate-800">{v.title}</td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={v.severity} />
                </td>
                <td className="px-4 py-3 text-slate-700">{v.cvss_score.toFixed(1)}</td>
                <td className="px-4 py-3 text-slate-700">
                  {v.ai_analysis?.ai_risk_score != null
                    ? v.ai_analysis.ai_risk_score.toFixed(1)
                    : "—"}
                </td>
                <td className="px-4 py-3">
                  <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-mono text-slate-600">
                    {v.source}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-500">
                  {v.affected_asset}
                </td>
                <td className="px-4 py-3 capitalize text-slate-500">{v.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [scan, setScan]       = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  useEffect(() => {
    if (!params?.id) return;
    getScanById(params.id)
      .then(setScan)
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Failed to load scan details")
      )
      .finally(() => setLoading(false));
  }, [params?.id]);

  // ---- Loading skeleton ----
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 p-6 md:p-8">
        <div className="mb-6 h-8 w-48 animate-pulse rounded-lg bg-slate-200" />
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-24 animate-pulse rounded-xl bg-slate-200" />
          ))}
        </div>
        <div className="mt-6 h-64 animate-pulse rounded-xl bg-slate-200" />
      </div>
    );
  }

  // ---- Error state ----
  if (error || !scan) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-slate-50 p-8 text-center">
        <AlertCircle className="h-12 w-12 text-red-400" />
        <h1 className="text-lg font-semibold text-slate-800">
          {error ?? "Scan not found"}
        </h1>
        <Link
          href="/history"
          className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </Link>
      </div>
    );
  }

  // ---- Derived values ----
  const criticalCount = scan.vulnerabilities.filter((v) => v.severity === "critical").length;
  const tau           = scan.metrics?.kendall_tau;
  const timeSaved     = scan.metrics?.time_saved_percent;

  return (
    <div className="min-h-screen bg-slate-50 p-6 md:p-8">
      {/* ------------------------------------------------------------------ */}
      {/* Back + header                                                        */}
      {/* ------------------------------------------------------------------ */}
      <div className="mb-6">
        <Link
          href="/history"
          className="mb-4 inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-800 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </Link>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="flex items-center gap-2 text-xl font-bold text-slate-900">
              <Target className="h-5 w-5 text-slate-400" />
              {scan.target}
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              Scan ID:{" "}
              <span className="font-mono text-xs text-slate-400">{scan.id}</span>
            </p>
          </div>

          {/* Report download */}
          {scan.report_path && (
            <a
              href={`${BASE_URL}/reports/${encodeURIComponent(
                scan.report_path.split("/").pop() ?? ""
              )}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 transition-colors"
            >
              <Download className="h-4 w-4" />
              Download PDF Report
            </a>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Metadata strip                                                       */}
      {/* ------------------------------------------------------------------ */}
      <div className="mb-6 flex flex-wrap gap-4 rounded-xl border border-slate-200 bg-white px-6 py-4 text-sm shadow-sm">
        <MetaItem label="Started" value={new Date(scan.timestamp).toLocaleString()} />
        <MetaItem label="Duration" value={`${scan.duration}s`} />
        <MetaItem
          label="Status"
          value={
            <span
              className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${
                scan.status === "complete"
                  ? "bg-green-100 text-green-700"
                  : scan.status === "error"
                  ? "bg-red-100 text-red-700"
                  : "bg-blue-100 text-blue-700"
              }`}
            >
              {scan.status}
            </span>
          }
        />
        <MetaItem
          label="Severity Breakdown"
          value={<SeveritySummaryBadges summary={scan.severity_summary} />}
        />
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Metric cards                                                         */}
      {/* ------------------------------------------------------------------ */}
      <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MetricCard
          label="Total Vulnerabilities"
          value={scan.vulnerability_count}
          icon={ShieldCheck}
        />
        <MetricCard
          label="Critical"
          value={criticalCount}
          icon={AlertCircle}
          className={criticalCount > 0 ? "border-red-200 bg-red-50" : ""}
        />
        <MetricCard
          label="Kendall's τ"
          value={tau != null ? tau.toFixed(3) : "—"}
          sub="Rank correlation (CVSS vs AI)"
          icon={Activity}
        />
        <MetricCard
          label="Time Saved"
          value={timeSaved != null ? `${timeSaved}%` : "—"}
          sub="vs manual CVSS review"
          icon={Clock}
          className="border-green-200 bg-green-50"
        />
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Vulnerability table                                                  */}
      {/* ------------------------------------------------------------------ */}
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
        Vulnerabilities ({scan.vulnerabilities.length})
      </h2>
      <VulnerabilityTable vulnerabilities={scan.vulnerabilities} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tiny inline metadata label/value pair
// ---------------------------------------------------------------------------
function MetaItem({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </span>
      <span className="text-slate-700">{value}</span>
    </div>
  );
}
