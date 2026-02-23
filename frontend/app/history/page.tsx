/**
 * app/history/page.tsx
 *
 * Scan History page — lists all past scans with target, timestamp, duration,
 * vulnerability count, severity breakdown, status and a link to the detail view.
 *
 * Data is fetched from GET /api/scans via the centralised API service.
 * Falls back gracefully when the backend has no scan-history endpoint yet.
 */

"use client";

import { useEffect, useState, useCallback } from "react";
import { RefreshCw, History } from "lucide-react";
import type { ScanSummary } from "@/types";
import { getScans } from "@/services/api";
import ScanHistoryTable from "@/components/history/ScanHistoryTable";

export default function HistoryPage() {
  const [scans, setScans]     = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getScans();
      // Sort newest first
      setScans([...data].sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ));
      setLastFetched(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan history");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  return (
    <div className="min-h-screen bg-slate-50 p-6 md:p-8">
      {/* ------------------------------------------------------------------ */}
      {/* Page header                                                         */}
      {/* ------------------------------------------------------------------ */}
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-900">
            <History className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900">Scan History</h1>
            <p className="text-sm text-slate-500">
              All past penetration test runs and their results
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {lastFetched && (
            <span className="text-xs text-slate-400">
              Last updated: {lastFetched.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={fetchScans}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Summary stats strip                                                 */}
      {/* ------------------------------------------------------------------ */}
      {!loading && scans.length > 0 && (
        <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard
            label="Total Scans"
            value={scans.length}
            className="bg-white"
          />
          <StatCard
            label="Completed"
            value={scans.filter((s) => s.status === "complete").length}
            className="bg-green-50"
            valueClass="text-green-700"
          />
          <StatCard
            label="Total Vulnerabilities"
            value={scans.reduce((sum, s) => sum + s.vulnerability_count, 0)}
            className="bg-orange-50"
            valueClass="text-orange-700"
          />
          <StatCard
            label="Avg Duration"
            value={
              scans.length
                ? `${Math.round(scans.reduce((s, x) => s + x.duration, 0) / scans.length)}s`
                : "—"
            }
            className="bg-slate-100"
          />
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* History table                                                       */}
      {/* ------------------------------------------------------------------ */}
      <ScanHistoryTable scans={scans} loading={loading} error={error} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small statistic card (reused only on this page)
// ---------------------------------------------------------------------------
function StatCard({
  label,
  value,
  className = "",
  valueClass = "text-slate-900",
}: {
  label: string;
  value: string | number;
  className?: string;
  valueClass?: string;
}) {
  return (
    <div className={`rounded-xl border border-slate-200 p-4 shadow-sm ${className}`}>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${valueClass}`}>{value}</p>
    </div>
  );
}
