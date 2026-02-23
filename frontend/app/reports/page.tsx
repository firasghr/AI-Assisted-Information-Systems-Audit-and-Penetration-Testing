"use client";

import { useEffect, useState } from "react";
import { getScans } from "@/services/api";
import type { ScanSummary } from "@/types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
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
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-800">Reports</h1>
        <button
          onClick={load}
          className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50"
        >
          Refresh
        </button>
      </div>

      {loading && (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="rounded-xl border bg-white p-4 animate-pulse">
              <div className="h-4 bg-slate-200 rounded w-1/3 mb-2" />
              <div className="h-3 bg-slate-100 rounded w-1/4" />
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-4 text-sm text-red-700 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={load} className="ml-4 font-semibold hover:underline">Retry</button>
        </div>
      )}

      {!loading && !error && scans.length === 0 && (
        <div className="rounded-xl border border-dashed border-slate-300 p-12 text-center text-slate-400 text-sm">
          No scan reports found. Run a scan from the Dashboard to generate reports.
        </div>
      )}

      {!loading && scans.length > 0 && (
        <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 bg-slate-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Target</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Date</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Vulnerabilities</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Status</th>
                <th className="px-4 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-50">
                  <td className="px-4 py-3 font-medium text-slate-800">{scan.target}</td>
                  <td className="px-4 py-3 text-slate-500">{new Date(scan.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-3 text-slate-600">{scan.vulnerability_count}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-semibold capitalize ${
                      scan.status === "complete" ? "bg-green-100 text-green-700" :
                      scan.status === "error" ? "bg-red-100 text-red-700" :
                      "bg-blue-100 text-blue-700"
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {scan.status === "complete" && (
                      <a
                        href={`${BASE_URL}/api/report/${encodeURIComponent(scan.id)}/download`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline text-xs font-medium mr-3"
                      >
                        Download PDF
                      </a>
                    )}
                    <a
                      href={`/history/${encodeURIComponent(scan.id)}`}
                      className="text-slate-500 hover:underline text-xs font-medium"
                    >
                      View Details
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
