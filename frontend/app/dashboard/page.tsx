"use client";

import { useState, useCallback } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  startPipeline,
  getScanById,
  getScanReport,
} from "@/services/api";
import type { Vulnerability, Metrics, PipelineResponse } from "@/types";

type ScanStatus = "idle" | "scanning" | "complete" | "error";
type SortKey = keyof Pick<Vulnerability, "title" | "severity" | "cvss_score" | "confidence" | "source" | "affected_asset"> | "ai_score" | "ai_rank";
type SortDir = "asc" | "desc";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  informational: "#64748b",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const PAGE_SIZE = 10;
const CHART_LABEL_MAX_LENGTH = 15;

function formatPieLabel({ name, percent }: { name?: string; percent?: number }) {
  return `${name ?? ""} ${((percent ?? 0) * 100).toFixed(0)}%`;
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-100 text-red-700",
    high: "bg-orange-100 text-orange-700",
    medium: "bg-yellow-100 text-yellow-700",
    low: "bg-green-100 text-green-700",
    informational: "bg-slate-100 text-slate-600",
  };
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-semibold capitalize ${colors[severity] ?? "bg-slate-100 text-slate-600"}`}>
      {severity}
    </span>
  );
}

function MetricCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className={`rounded-xl border bg-white p-4 shadow-sm`}>
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="mt-0.5 text-xs text-slate-400">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [target, setTarget] = useState("");
  const [scanStatus, setScanStatus] = useState<ScanStatus>("idle");
  const [statusMessage, setStatusMessage] = useState("Idle");
  const [error, setError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [reportPath, setReportPath] = useState<string | null>(null);
  const [reportGeneratedAt, setReportGeneratedAt] = useState<string | null>(null);

  // Table state
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
    setPage(1);
  };

  const handleScan = useCallback(async () => {
    if (!target.trim()) {
      setError("Please enter a target domain or IP address.");
      return;
    }
    setError(null);
    setScanStatus("scanning");
    setStatusMessage("Scanning…");
    setMetrics(null);
    setVulnerabilities([]);
    setReportPath(null);

    try {
      setStatusMessage("AI Analysis…");
      const res: PipelineResponse = await startPipeline(target.trim());

      setStatusMessage("Generating Report…");
      if (res.metrics) setMetrics(res.metrics);

      // Load full scan detail
      if (res.report_path) {
        try {
          // Try to get scans list to find the latest one
          const { getScans } = await import("@/services/api");
          const scans = await getScans();
          if (scans.length > 0) {
            const latest = scans[scans.length - 1];
            const detail = await getScanById(latest.id);
            if (detail.vulnerabilities) setVulnerabilities(detail.vulnerabilities);
            if (detail.metrics) setMetrics(detail.metrics);
            // Get report
            try {
              const report = await getScanReport(latest.id);
              setReportPath(report.report_path);
              setReportGeneratedAt(report.generated_at ?? null);
            } catch {
              setReportPath(res.report_path);
            }
          }
        } catch {
          setReportPath(res.report_path);
        }
      }

      setScanStatus("complete");
      setStatusMessage("Complete");
    } catch (err) {
      setScanStatus("error");
      setStatusMessage("Error");
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    }
  }, [target]);

  // Filtered + sorted vulnerabilities
  const filtered = vulnerabilities
    .filter((v) => severityFilter === "all" || v.severity === severityFilter)
    .filter(
      (v) =>
        !search ||
        v.title.toLowerCase().includes(search.toLowerCase()) ||
        v.affected_asset.toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") {
        cmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
      } else if (sortKey === "cvss_score") {
        cmp = a.cvss_score - b.cvss_score;
      } else if (sortKey === "ai_score") {
        cmp = (a.ai_analysis?.ai_risk_score ?? 0) - (b.ai_analysis?.ai_risk_score ?? 0);
      } else if (sortKey === "ai_rank") {
        cmp = (a.ai_analysis?.priority_rank ?? 999) - (b.ai_analysis?.priority_rank ?? 999);
      } else if (sortKey === "title") {
        cmp = a.title.localeCompare(b.title);
      } else if (sortKey === "confidence") {
        cmp = a.confidence.localeCompare(b.confidence);
      } else if (sortKey === "source") {
        cmp = a.source.localeCompare(b.source);
      } else if (sortKey === "affected_asset") {
        cmp = a.affected_asset.localeCompare(b.affected_asset);
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Chart data
  const severityChartData = metrics
    ? Object.entries(metrics.severity_distribution).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        count: value,
        fill: SEVERITY_COLORS[name] ?? "#64748b",
      }))
    : [];

  const aiVsCvssData = (metrics?.ranking_comparison ?? []).slice(0, 20).map((r) => ({
    name: r.title.substring(0, CHART_LABEL_MAX_LENGTH) + (r.title.length > CHART_LABEL_MAX_LENGTH ? "…" : ""),
    cvss: r.cvss_score,
    ai: r.ai_risk_score,
  }));

  const sourceData = (() => {
    const counts: Record<string, number> = {};
    vulnerabilities.forEach((v) => {
      counts[v.source] = (counts[v.source] ?? 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  })();

  const rankCompData = (metrics?.ranking_comparison ?? []).slice(0, 15).map((r) => ({
    name: r.id.substring(0, 8),
    traditional: r.traditional_rank,
    ai: r.ai_rank,
  }));

  const SortIcon = ({ col }: { col: SortKey }) =>
    sortKey === col ? (sortDir === "asc" ? " ↑" : " ↓") : " ⇅";

  const th = "px-3 py-2 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-800 whitespace-nowrap select-none";

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
      {/* Section 1: Scan Control */}
      <div className="rounded-xl border bg-white shadow-sm p-6">
        <h2 className="text-lg font-semibold text-slate-800 mb-4">Scan Control Panel</h2>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Enter target domain or IP (e.g. 192.168.1.1)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && scanStatus !== "scanning" && handleScan()}
            disabled={scanStatus === "scanning"}
            className="flex-1 rounded-lg border border-slate-300 px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <button
            onClick={handleScan}
            disabled={scanStatus === "scanning"}
            className="flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            {scanStatus === "scanning" && (
              <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
            )}
            {scanStatus === "scanning" ? "Scanning…" : "Start Scan"}
          </button>
        </div>
        <div className="mt-3 flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${
              scanStatus === "idle"
                ? "bg-slate-400"
                : scanStatus === "scanning"
                ? "bg-blue-500 animate-pulse"
                : scanStatus === "complete"
                ? "bg-green-500"
                : "bg-red-500"
            }`}
          />
          <span className="text-sm text-slate-600">{statusMessage}</span>
        </div>
        {error && (
          <div className="mt-3 rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700 flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="ml-4 text-red-500 hover:text-red-700 font-semibold">
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Section 2: Metric Cards */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <MetricCard
            label="Total Vulnerabilities"
            value={metrics.total_vulnerabilities}
            color="text-blue-600"
          />
          <MetricCard
            label="Critical"
            value={metrics.severity_distribution.critical}
            color="text-red-600"
          />
          <MetricCard
            label="Divergent Rankings"
            value={`${metrics.divergent_rankings_percent.toFixed(1)}%`}
            sub={`${metrics.divergent_rankings_count} differ`}
            color="text-purple-600"
          />
          <MetricCard
            label="Time Saved"
            value={`${metrics.time_saved_percent.toFixed(1)}%`}
            sub={`${Math.round(metrics.time_saved_seconds)}s saved`}
            color="text-green-600"
          />
          <MetricCard
            label="Kendall&apos;s τ"
            value={metrics.kendall_tau.toFixed(3)}
            sub={metrics.kendall_tau_interpretation}
            color="text-indigo-600"
          />
        </div>
      )}

      {/* Section 3: Vulnerability Table */}
      {vulnerabilities.length > 0 && (
        <div className="rounded-xl border bg-white shadow-sm p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h2 className="text-lg font-semibold text-slate-800">
              Vulnerability Overview ({filtered.length})
            </h2>
            <div className="flex flex-wrap gap-2">
              <input
                type="search"
                placeholder="Search…"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <select
                value={severityFilter}
                onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Informational</option>
              </select>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-200">
                <tr>
                  <th className={th} onClick={() => handleSort("title")}>Title<SortIcon col="title" /></th>
                  <th className={th} onClick={() => handleSort("severity")}>Severity<SortIcon col="severity" /></th>
                  <th className={th} onClick={() => handleSort("cvss_score")}>CVSS<SortIcon col="cvss_score" /></th>
                  <th className={th} onClick={() => handleSort("ai_score")}>AI Score<SortIcon col="ai_score" /></th>
                  <th className={th} onClick={() => handleSort("ai_rank")}>AI Rank<SortIcon col="ai_rank" /></th>
                  <th className={th} onClick={() => handleSort("confidence")}>Confidence<SortIcon col="confidence" /></th>
                  <th className={th} onClick={() => handleSort("source")}>Source<SortIcon col="source" /></th>
                  <th className={th} onClick={() => handleSort("affected_asset")}>Asset<SortIcon col="affected_asset" /></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {paginated.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-50">
                    <td className="px-3 py-2 font-medium text-slate-800 max-w-xs truncate" title={v.title}>{v.title}</td>
                    <td className="px-3 py-2"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-3 py-2 text-slate-600">{v.cvss_score.toFixed(1)}</td>
                    <td className="px-3 py-2 text-slate-600">{v.ai_analysis?.ai_risk_score?.toFixed(1) ?? "—"}</td>
                    <td className="px-3 py-2 text-slate-600">{v.ai_analysis?.priority_rank ?? "—"}</td>
                    <td className="px-3 py-2 capitalize text-slate-600">{v.confidence}</td>
                    <td className="px-3 py-2 text-slate-600">{v.source}</td>
                    <td className="px-3 py-2 text-slate-600 max-w-xs truncate" title={v.affected_asset}>{v.affected_asset}</td>
                  </tr>
                ))}
                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-3 py-8 text-center text-slate-400">No vulnerabilities match your filters.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between text-sm text-slate-600">
              <span>Page {page} of {totalPages}</span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="rounded px-3 py-1 border border-slate-300 disabled:opacity-40 hover:bg-slate-50"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="rounded px-3 py-1 border border-slate-300 disabled:opacity-40 hover:bg-slate-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Section 4: Charts */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart 1: Severity Distribution */}
          <div className="rounded-xl border bg-white shadow-sm p-6">
            <h3 className="text-sm font-semibold text-slate-700 mb-4">Vulnerabilities by Severity</h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityChartData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Chart 2: AI Score vs CVSS */}
          {aiVsCvssData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4">AI Risk Score vs CVSS Score</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={aiVsCvssData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 12 }} domain={[0, 10]} />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="cvss" name="CVSS" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="ai" name="AI Score" fill="#8b5cf6" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Chart 3: Source Pie */}
          {sourceData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4">Vulnerabilities by Source</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={sourceData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={formatPieLabel}>
                    {sourceData.map((_, idx) => (
                      <Cell key={idx} fill={["#3b82f6", "#8b5cf6", "#22c55e", "#f97316"][idx % 4]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Chart 4: AI Rank vs Traditional Rank */}
          {rankCompData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4">AI Rank vs Traditional Rank</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={rankCompData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="traditional" name="Traditional" fill="#94a3b8" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="ai" name="AI" fill="#6366f1" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* Section 5: AI vs Traditional Analysis */}
      {metrics && (
        <div className="rounded-xl border bg-white shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-800 mb-4">AI vs Traditional Analysis</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-4">
            <div className="rounded-lg bg-indigo-50 p-3">
              <p className="text-xs text-indigo-600 font-medium">Kendall&apos;s τ</p>
              <p className="text-xl font-bold text-indigo-700">{metrics.kendall_tau.toFixed(3)}</p>
              <p className="text-xs text-indigo-500 mt-0.5">{metrics.kendall_tau_interpretation}</p>
            </div>
            <div className="rounded-lg bg-blue-50 p-3">
              <p className="text-xs text-blue-600 font-medium">Avg CVSS</p>
              <p className="text-xl font-bold text-blue-700">{metrics.avg_cvss_score.toFixed(2)}</p>
            </div>
            <div className="rounded-lg bg-purple-50 p-3">
              <p className="text-xs text-purple-600 font-medium">Avg AI Score</p>
              <p className="text-xl font-bold text-purple-700">{metrics.avg_ai_risk_score.toFixed(2)}</p>
            </div>
            <div className="rounded-lg bg-red-50 p-3">
              <p className="text-xs text-red-600 font-medium">False Positives</p>
              <p className="text-xl font-bold text-red-700">{metrics.false_positives_detected_count}</p>
              <p className="text-xs text-red-500 mt-0.5">{metrics.false_positives_probable_count} probable</p>
            </div>
            <div className="rounded-lg bg-green-50 p-3">
              <p className="text-xs text-green-600 font-medium">Time Saved</p>
              <p className="text-xl font-bold text-green-700">{metrics.time_saved_percent.toFixed(1)}%</p>
              <p className="text-xs text-green-500 mt-0.5">{Math.round(metrics.time_saved_seconds)}s</p>
            </div>
          </div>
          <p className="text-sm text-slate-500 leading-relaxed">
            The AI pipeline ranked {metrics.divergent_rankings_count} vulnerabilities differently from traditional CVSS-based ordering
            ({metrics.divergent_rankings_percent.toFixed(1)}% divergence), using the {metrics.ai_model} model.
            Kendall&apos;s τ of {metrics.kendall_tau.toFixed(3)} indicates {metrics.kendall_tau_interpretation.toLowerCase()}.
            Total AI tokens used: {metrics.ai_tokens_used.toLocaleString()}.
          </p>
        </div>
      )}

      {/* Section 6: Report Management */}
      {scanStatus === "complete" && (
        <div className="rounded-xl border bg-white shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-800 mb-4">Report Management</h2>
          <div className="flex items-center gap-4 flex-wrap">
            {reportPath && (
              <a
                href={`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000"}/api/report/download?path=${encodeURIComponent(reportPath)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 rounded-lg bg-green-600 px-5 py-2 text-sm font-semibold text-white hover:bg-green-700 transition-colors"
              >
                Download PDF Report
              </a>
            )}
            {!reportPath && (
              <span className="text-sm text-slate-500">No report available for this scan.</span>
            )}
            {reportGeneratedAt && (
              <span className="text-sm text-slate-400">
                Generated: {new Date(reportGeneratedAt).toLocaleString()}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Empty state */}
      {scanStatus === "idle" && (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center">
          <p className="text-slate-400 text-sm">Enter a target above and click <strong>Start Scan</strong> to begin.</p>
        </div>
      )}
    </div>
  );
}
