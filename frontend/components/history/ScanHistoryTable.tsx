/**
 * components/history/ScanHistoryTable.tsx
 *
 * Renders the full scan history table.
 *
 * Features:
 *  - Columns: target, timestamp, duration, vuln count, severity summary, status, detail link
 *  - Click "View Details" to navigate to /history/[id]
 *  - Empty state with helpful prompt
 *  - Loading skeleton rows
 *  - Error banner
 */

"use client";

import Link from "next/link";
import type { ScanSummary } from "@/types";
import SeveritySummaryBadges from "./SeveritySummaryBadges";
import { Clock, Target, ShieldAlert, ArrowRight } from "lucide-react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}



// ---------------------------------------------------------------------------
// Skeleton row shown while loading
// ---------------------------------------------------------------------------
function SkeletonRow() {
  return (
    <tr className="animate-pulse">
      {Array.from({ length: 7 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 rounded bg-slate-200" />
        </td>
      ))}
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
interface Props {
  scans: ScanSummary[];
  loading: boolean;
  error: string | null;
}

export default function ScanHistoryTable({ scans, loading, error }: Props) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      {/* Error banner */}
      {error && (
        <div className="border-b border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/50 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">
                <span className="flex items-center gap-1.5">
                  <Target className="h-3.5 w-3.5" />
                  Target
                </span>
              </th>
              <th className="px-4 py-3">
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" />
                  Timestamp
                </span>
              </th>
              <th className="px-4 py-3">Duration</th>
              <th className="px-4 py-3">
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Vulns
                </span>
              </th>
              <th className="px-4 py-3">Severity Breakdown</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">Details</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-100">
            {/* Loading skeletons */}
            {loading && Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} />)}

            {/* Empty state */}
            {!loading && !error && scans.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-slate-400">
                  <ShieldAlert className="mx-auto mb-2 h-8 w-8 opacity-40" />
                  <p className="font-medium">No scan history yet</p>
                  <p className="mt-1 text-xs">Run a scan from the Dashboard to see results here.</p>
                </td>
              </tr>
            )}

            {/* Data rows */}
            {!loading &&
              scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="transition-colors hover:bg-slate-50/80"
                >
                  {/* Target */}
                  <td className="px-4 py-3 font-mono text-slate-800">
                    {scan.target}
                  </td>

                  {/* Timestamp */}
                  <td className="px-4 py-3 text-slate-500">
                    {formatTimestamp(scan.timestamp)}
                  </td>

                  {/* Duration */}
                  <td className="px-4 py-3 text-slate-500">
                    {formatDuration(scan.duration)}
                  </td>

                  {/* Vuln count */}
                  <td className="px-4 py-3 font-semibold text-slate-800">
                    {scan.vulnerability_count}
                  </td>

                  {/* Severity summary */}
                  <td className="px-4 py-3">
                    <SeveritySummaryBadges summary={scan.severity_summary} />
                  </td>

                  {/* Status badge */}
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset ${
                        scan.status === "complete"
                          ? "bg-green-100 text-green-700 ring-green-600/20"
                          : scan.status === "error"
                          ? "bg-red-100 text-red-700 ring-red-600/20"
                          : scan.status === "running"
                          ? "bg-blue-100 text-blue-700 ring-blue-600/20"
                          : "bg-slate-100 text-slate-600 ring-slate-500/20"
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>

                  {/* View details */}
                  <td className="px-4 py-3 text-right">
                    <Link
                      href={`/history/${scan.id}`}
                      className="inline-flex items-center gap-1 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-blue-700 shadow-sm"
                    >
                      View
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* Footer: total count */}
      {!loading && scans.length > 0 && (
        <div className="border-t border-slate-100 px-4 py-2 text-right text-xs text-slate-400">
          {scans.length} scan{scans.length !== 1 ? "s" : ""} total
        </div>
      )}
    </div>
  );
}
