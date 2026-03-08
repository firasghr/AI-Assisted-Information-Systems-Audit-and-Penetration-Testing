/**
 * app/status/page.tsx
 *
 * System Status page — backend health, scan statistics, API endpoints.
 */

"use client";

import { useEffect, useState, useCallback } from "react";
import { checkHealth, getScans } from "@/services/api";
import type { HealthResponse, ScanSummary } from "@/types";
import {
  Activity,
  RefreshCw,
  Server,
  Wifi,
  WifiOff,
  BarChart3,
  Globe,
  Clock,
  Target,
  CheckCircle2,
  XCircle,
} from "lucide-react";

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
  const totalVulns = scans.reduce((sum, s) => sum + s.vulnerability_count, 0);

  const endpoints = [
    { method: "GET",  path: "/health",             desc: "Health check" },
    { method: "POST", path: "/api/pipeline",       desc: "Full scan pipeline" },
    { method: "POST", path: "/api/scan/nmap",      desc: "Nmap network scan" },
    { method: "POST", path: "/api/scan/zap",       desc: "ZAP web scan" },
    { method: "POST", path: "/api/normalize",      desc: "Normalize findings" },
    { method: "POST", path: "/api/analyze",        desc: "AI analysis" },
    { method: "POST", path: "/api/compare",        desc: "Compare rankings" },
    { method: "POST", path: "/api/report",         desc: "Generate report" },
    { method: "GET",  path: "/api/scans",          desc: "Scan history" },
    { method: "GET",  path: "/api/scans/:id",      desc: "Scan detail" },
    { method: "GET",  path: "/api/vulnerabilities", desc: "Vulnerabilities" },
    { method: "GET",  path: "/api/metrics",        desc: "Metrics" },
  ];

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-blue-100 p-2.5">
            <Activity className="h-5 w-5 text-blue-600" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-800">System Status</h1>
            <p className="text-xs text-slate-400">Backend health, API status, and scan statistics</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-slate-400">
              Updated: {lastRefresh.toLocaleTimeString()} (auto every 30s)
            </span>
          )}
          <button
            onClick={refresh}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700 flex items-center gap-2">
          <XCircle className="h-4 w-4 shrink-0" /> {error}
        </div>
      )}

      {/* Top cards: Backend + Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Backend status card */}
        <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Backend API</p>
              {loading ? (
                <div className="mt-2 h-6 w-20 animate-pulse rounded bg-slate-200" />
              ) : (
                <div className="flex items-center gap-2 mt-1.5">
                  <span className={`h-2.5 w-2.5 rounded-full ${health ? "bg-green-500" : "bg-red-500"}`} />
                  <p className={`text-xl font-bold ${health ? "text-green-600" : "text-red-600"}`}>
                    {health ? "Online" : "Offline"}
                  </p>
                </div>
              )}
              {health && <p className="mt-0.5 text-xs text-slate-400">v{health.version}</p>}
            </div>
            <div className={`rounded-lg p-2.5 ${health ? "bg-green-50" : "bg-red-50"}`}>
              {health ? <Wifi className="h-5 w-5 text-green-600" /> : <WifiOff className="h-5 w-5 text-red-600" />}
            </div>
          </div>
        </div>

        {/* Completed scans */}
        <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Completed Scans</p>
              <p className="mt-1.5 text-2xl font-bold text-blue-600">{loading ? "—" : completedScans}</p>
              <p className="mt-0.5 text-xs text-slate-400">{scans.length} total</p>
            </div>
            <div className="rounded-lg p-2.5 bg-blue-50">
              <BarChart3 className="h-5 w-5 text-blue-600" />
            </div>
          </div>
        </div>

        {/* Total vulns */}
        <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Total Vulnerabilities</p>
              <p className="mt-1.5 text-2xl font-bold text-orange-600">{loading ? "—" : totalVulns}</p>
              <p className="mt-0.5 text-xs text-slate-400">across all scans</p>
            </div>
            <div className="rounded-lg p-2.5 bg-orange-50">
              <Target className="h-5 w-5 text-orange-600" />
            </div>
          </div>
        </div>

        {/* Last scan */}
        <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Last Scan</p>
              <p className="mt-1.5 text-lg font-bold text-slate-700 truncate">
                {lastScan ? new Date(lastScan.timestamp).toLocaleDateString() : "—"}
              </p>
              {lastScan && <p className="mt-0.5 text-xs text-slate-400 truncate">{lastScan.target}</p>}
            </div>
            <div className="rounded-lg p-2.5 bg-slate-100">
              <Clock className="h-5 w-5 text-slate-600" />
            </div>
          </div>
        </div>
      </div>

      {/* API Endpoints */}
      <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
        <div className="flex items-center gap-3 p-5 border-b border-slate-100">
          <div className="rounded-lg bg-indigo-100 p-2">
            <Globe className="h-4 w-4 text-indigo-600" />
          </div>
          <h2 className="text-lg font-semibold text-slate-800">API Endpoints</h2>
          <div className="ml-auto flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-full ${health ? "bg-green-500" : "bg-slate-300"}`} />
            <span className="text-xs text-slate-400">{health ? "All endpoints active" : "Backend offline"}</span>
          </div>
        </div>
        <div className="divide-y divide-slate-50">
          {endpoints.map((ep) => (
            <div key={ep.path + ep.method} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50/50 transition-colors">
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md min-w-[42px] text-center ${
                ep.method === "GET" ? "bg-blue-100 text-blue-700" : "bg-orange-100 text-orange-700"
              }`}>
                {ep.method}
              </span>
              <code className="text-xs text-slate-700 font-mono flex-1">{ep.path}</code>
              <span className="text-xs text-slate-400">{ep.desc}</span>
              {health ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
              ) : (
                <XCircle className="h-3.5 w-3.5 text-slate-300 shrink-0" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Recent Scans */}
      {!loading && scans.length > 0 && (
        <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
          <div className="flex items-center gap-3 p-5 border-b border-slate-100">
            <div className="rounded-lg bg-green-100 p-2">
              <Server className="h-4 w-4 text-green-600" />
            </div>
            <h2 className="text-lg font-semibold text-slate-800">Recent Scans</h2>
          </div>
          <div className="divide-y divide-slate-50">
            {scans.slice(0, 5).map((scan) => (
              <div key={scan.id} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-50/50 transition-colors">
                <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                  scan.status === "complete" ? "bg-green-500" :
                  scan.status === "error" ? "bg-red-500" : "bg-blue-500"
                }`} />
                <span className="font-medium text-slate-700 truncate flex-1 text-sm">{scan.target}</span>
                <span className="text-xs text-slate-400">{new Date(scan.timestamp).toLocaleString()}</span>
                <span className="text-xs font-semibold text-slate-600">{scan.vulnerability_count} vulns</span>
                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold capitalize ring-1 ring-inset ${
                  scan.status === "complete" ? "bg-green-100 text-green-700 ring-green-600/20" :
                  scan.status === "error" ? "bg-red-100 text-red-700 ring-red-600/20" :
                  "bg-blue-100 text-blue-700 ring-blue-600/20"
                }`}>
                  {scan.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
