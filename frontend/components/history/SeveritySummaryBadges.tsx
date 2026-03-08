/**
 * components/history/SeveritySummaryBadges.tsx
 *
 * Renders a compact row of colour-coded severity count badges for a scan row.
 * Only non-zero counts are shown to keep the table compact.
 */

import type { ScanSeveritySummary } from "@/types";

interface Props {
  summary: ScanSeveritySummary;
}

type SeverityKey = keyof ScanSeveritySummary;

const SEVERITY_STYLES: Record<SeverityKey, { bg: string; text: string; label: string }> = {
  critical:      { bg: "bg-red-100 ring-1 ring-inset ring-red-600/20",       text: "text-red-700",    label: "C" },
  high:          { bg: "bg-orange-100 ring-1 ring-inset ring-orange-600/20", text: "text-orange-700", label: "H" },
  medium:        { bg: "bg-yellow-100 ring-1 ring-inset ring-yellow-600/20", text: "text-yellow-700", label: "M" },
  low:           { bg: "bg-green-100 ring-1 ring-inset ring-green-600/20",   text: "text-green-700",  label: "L" },
  informational: { bg: "bg-slate-100 ring-1 ring-inset ring-slate-500/20",   text: "text-slate-600",  label: "I" },
};

export default function SeveritySummaryBadges({ summary }: Props) {
  const keys: SeverityKey[] = ["critical", "high", "medium", "low", "informational"];

  return (
    <span className="flex flex-wrap gap-1">
      {keys.map((key) => {
        const count = summary[key];
        if (count === 0) return null;
        const { bg, text, label } = SEVERITY_STYLES[key];
        return (
          <span
            key={key}
            title={`${key}: ${count}`}
            className={`inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs font-semibold ${bg} ${text}`}
          >
            {label}
            <span className="font-normal">{count}</span>
          </span>
        );
      })}
    </span>
  );
}
