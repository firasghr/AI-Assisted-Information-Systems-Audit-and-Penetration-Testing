/**
 * app/reports/page.tsx
 *
 * Reports page — lists all generated PDF reports with download links.
 */

"use client";

import { useEffect, useState, useCallback } from "react";
import { getScans } from "@/services/api";
import type { ScanSummary } from "@/types";
import {
  FileText,
  Download,
  RefreshCw,
  ExternalLink,
  Shield,
  Clock,
  Target,
} from "lucide-react";
import Link from "next/link";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getScans();
      setScans(data.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const completedScans = scans.filter((s) => s.status === "complete");

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-blue-100 p-2.5">
            <FileText className="h-5 w-5 text-blue-600" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-800">Reports</h1>
            <p className="text-xs text-slate-400">Download generated penetration testing PDF reports</p>
          </div>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Summary stat */}
      {!loading && scans.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
          <StatCard label="Total Reports" value={completedScans.length} icon={FileText} bgColor="bg-blue-50" color="text-blue-600" />
          <StatCard label="Total Scans" value={scans.length} icon={Shield} bgColor="bg-slate-100" color="text-slate-600" />
          <StatCard label="Latest Report" value={
            completedScans.length > 0
              ? new Date(completedScans[0].timestamp).toLocaleDateString()
              : "—"
          } icon={Clock} bgColor="bg-green-50" color="text-green-600" />
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-xl border bg-white p-5 animate-pulse">
              <div className="h-4 bg-slate-200 rounded w-1/3 mb-2" />
              <div className="h-3 bg-slate-100 rounded w-1/4" />
            </div>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={load} className="ml-4 font-semibold text-red-600 hover:underline">Retry</button>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && scans.length === 0 && (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-16 text-center">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-slate-100 flex items-center justify-center mb-4">
            <FileText className="h-8 w-8 text-slate-300" />
          </div>
          <h3 className="text-lg font-semibold text-slate-600 mb-1">No Reports Yet</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Run a scan from the Dashboard to generate penetration testing reports.
          </p>
        </div>
      )}

      {/* Reports table */}
      {!loading && scans.length > 0 && (
        <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-200 bg-slate-50/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                    <span className="flex items-center gap-1.5"><Target className="h-3.5 w-3.5" /> Target</span>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                    <span className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> Date</span>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Vulnerabilities</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Status</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-800">{scan.target}</td>
                    <td className="px-4 py-3 text-slate-500">{new Date(scan.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <span className="font-semibold text-slate-700">{scan.vulnerability_count}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold capitalize ring-1 ring-inset ${
                        scan.status === "complete" ? "bg-green-100 text-green-700 ring-green-600/20" :
                        scan.status === "error" ? "bg-red-100 text-red-700 ring-red-600/20" :
                        "bg-blue-100 text-blue-700 ring-blue-600/20"
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {scan.status === "complete" && (
                          <a
                            href={`${BASE_URL}/api/report/${encodeURIComponent(scan.id)}/download`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 transition-colors shadow-sm"
                          >
                            <Download className="h-3.5 w-3.5" /> PDF
                          </a>
                        )}
                        <Link
                          href={`/history/${encodeURIComponent(scan.id)}`}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors"
                        >
                          <ExternalLink className="h-3.5 w-3.5" /> Details
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="border-t border-slate-100 px-4 py-2 text-right text-xs text-slate-400">
            {scans.length} scan{scans.length !== 1 ? "s" : ""} total
          </div>
        </div>
      )}
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
