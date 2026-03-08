/**
 * app/history/page.tsx
 *
 * Scan History page — lists all past scans with consistent UI.
 */

"use client";

import { useEffect, useState, useCallback } from "react";
import { RefreshCw, History, ShieldAlert, Clock, CheckCircle2 } from "lucide-react";
import type { ScanSummary } from "@/types";
import { getScans } from "@/services/api";
import ScanHistoryTable from "@/components/history/ScanHistoryTable";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getScans();
      setScans([...data].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
      setLastFetched(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan history");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  const completedCount = scans.filter((s) => s.status === "complete").length;
  const totalVulns = scans.reduce((sum, s) => sum + s.vulnerability_count, 0);
  const avgDuration = scans.length
    ? `${Math.round(scans.reduce((s, x) => s + x.duration, 0) / scans.length)}s`
    : "—";

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-blue-100 p-2.5">
            <History className="h-5 w-5 text-blue-600" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-800">Scan History</h1>
            <p className="text-xs text-slate-400">All past penetration test runs and their results</p>
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
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary stats */}
      {!loading && scans.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Total Scans" value={scans.length} icon={History} bgColor="bg-blue-50" color="text-blue-600" />
          <StatCard label="Completed" value={completedCount} icon={CheckCircle2} bgColor="bg-green-50" color="text-green-600" />
          <StatCard label="Total Vulnerabilities" value={totalVulns} icon={ShieldAlert} bgColor="bg-orange-50" color="text-orange-600" />
          <StatCard label="Avg Duration" value={avgDuration} icon={Clock} bgColor="bg-slate-100" color="text-slate-600" />
        </div>
      )}

      {/* History table */}
      <ScanHistoryTable scans={scans} loading={loading} error={error} />
    </div>
  );
}

function StatCard({ label, value, icon: Icon, bgColor, color }: {
  label: string; value: string | number; icon: React.ElementType; bgColor: string; color: string;
}) {
  return (
    <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
          <p className={`mt-1.5 text-2xl font-bold ${color}`}>{value}</p>
        </div>
        <div className={`rounded-lg p-2.5 ${bgColor}`}>
          <Icon className={`h-5 w-5 ${color}`} />
        </div>
      </div>
    </div>
  );
}
