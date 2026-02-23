"use client";

import { useEffect, useState, useCallback } from "react";
import { checkHealth, getScans } from "@/services/api";
import type { HealthResponse, ScanSummary } from "@/types";

export default function StatusPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, s] = await Promise.allSettled([checkHealth(), getScans()]);
      if (h.status === "fulfilled") setHealth(h.value);
      else setHealth(null);
      if (s.status === "fulfilled") setScans(s.value);
      else setScans([]);
      if (h.status === "rejected") setError("Backend is unreachable.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch status.");
    } finally {
      setLoading(false);
      setLastRefresh(new Date());
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 30_000);
    return () => clearInterval(interval);
  }, [refresh]);

  const lastScan = scans.length > 0
    ? scans.reduce((a, b) => new Date(a.timestamp) > new Date(b.timestamp) ? a : b)
    : null;

  const completedScans = scans.filter((s) => s.status === "complete").length;

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-800">System Status</h1>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-slate-400">
              Refreshed: {lastRefresh.toLocaleTimeString()} (auto every 30s)
            </span>
          )}
          <button
            onClick={refresh}
            disabled={loading}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50"
          >
            Refresh Now
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Backend Status */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        <div className="rounded-xl border bg-white shadow-sm p-5">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Backend API</h2>
          {loading ? (
            <div className="animate-pulse space-y-2">
              <div className="h-5 bg-slate-200 rounded w-1/3" />
              <div className="h-3 bg-slate-100 rounded w-1/2" />
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <span className={`h-3 w-3 rounded-full ${health ? "bg-green-500" : "bg-red-500"}`} />
              <div>
                <p className={`font-semibold ${health ? "text-green-700" : "text-red-700"}`}>
                  {health ? "Online" : "Offline"}
                </p>
                {health && <p className="text-xs text-slate-400 mt-0.5">v{health.version} — {new Date(health.timestamp).toLocaleString()}</p>}
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border bg-white shadow-sm p-5">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Scan Statistics</h2>
          {loading ? (
            <div className="animate-pulse space-y-2">
              <div className="h-5 bg-slate-200 rounded w-1/2" />
              <div className="h-3 bg-slate-100 rounded w-1/3" />
            </div>
          ) : (
            <div className="space-y-1.5">
              <p className="text-sm text-slate-700">
                <span className="font-semibold text-2xl text-slate-800">{completedScans}</span>
                <span className="text-slate-400 ml-1 text-xs">completed scans</span>
              </p>
              <p className="text-xs text-slate-400">
                {lastScan
                  ? `Last scan: ${new Date(lastScan.timestamp).toLocaleString()} — ${lastScan.target}`
                  : "No scans yet"}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* API Endpoints Status */}
      <div className="rounded-xl border bg-white shadow-sm p-5">
        <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-4">API Endpoints</h2>
        <div className="space-y-2">
          {[
            { method: "GET", path: "/health", desc: "Health check" },
            { method: "POST", path: "/api/pipeline", desc: "Full scan pipeline" },
            { method: "GET", path: "/api/scans", desc: "Scan history" },
            { method: "GET", path: "/api/scans/:id", desc: "Scan detail" },
            { method: "GET", path: "/api/metrics", desc: "Latest metrics" },
            { method: "GET", path: "/api/vulnerabilities", desc: "Latest vulnerabilities" },
            { method: "GET", path: "/api/report", desc: "Report download" },
          ].map((ep) => (
            <div key={ep.path} className="flex items-center gap-3 py-1.5 border-b border-slate-50 last:border-0">
              <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                ep.method === "GET" ? "bg-blue-100 text-blue-700" : "bg-orange-100 text-orange-700"
              }`}>
                {ep.method}
              </span>
              <code className="text-xs text-slate-600 font-mono">{ep.path}</code>
              <span className="text-xs text-slate-400 ml-auto">{ep.desc}</span>
              <span className={`h-1.5 w-1.5 rounded-full ${health ? "bg-green-400" : "bg-slate-300"}`} />
            </div>
          ))}
        </div>
      </div>

      {/* Recent Scans */}
      {!loading && scans.length > 0 && (
        <div className="mt-4 rounded-xl border bg-white shadow-sm p-5">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-4">Recent Scans</h2>
          <div className="space-y-2">
            {scans.slice(0, 5).map((scan) => (
              <div key={scan.id} className="flex items-center gap-3 text-sm">
                <span className={`h-2 w-2 rounded-full flex-shrink-0 ${
                  scan.status === "complete" ? "bg-green-500" :
                  scan.status === "error" ? "bg-red-500" : "bg-blue-500"
                }`} />
                <span className="font-medium text-slate-700 truncate flex-1">{scan.target}</span>
                <span className="text-slate-400 text-xs">{new Date(scan.timestamp).toLocaleDateString()}</span>
                <span className="text-slate-500">{scan.vulnerability_count} vulns</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
