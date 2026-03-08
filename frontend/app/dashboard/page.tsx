"use client";

import React, { useState, useCallback, useRef, useEffect } from "react";
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
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from "recharts";
import {
  startNmapScan,
  startZapScan,
  runNormalize,
  runAnalyze,
  runCompare,
  generateReport,
} from "@/services/api";
import type { Vulnerability, Metrics } from "@/types";
import {
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Bug,
  Brain,
  GitCompare,
  FileText,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Radar as RadarIcon,
  Target,
  Zap,
  TrendingUp,
  Timer,
  BarChart3,
} from "lucide-react";

/* ───────────────────────── constants ───────────────────────── */

type ScanPhase = "idle" | "nmap" | "zap" | "normalize" | "analyze" | "compare" | "report" | "complete" | "error";
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
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
};

const PAGE_SIZE = 10;

interface PipelineStep {
  id: ScanPhase;
  label: string;
  icon: React.ReactNode;
  description: string;
}

const PIPELINE_STEPS: PipelineStep[] = [
  { id: "nmap",      label: "Network Scan",    icon: <RadarIcon className="h-5 w-5" />,   description: "Nmap port & service discovery" },
  { id: "zap",       label: "Web App Scan",    icon: <Zap className="h-5 w-5" />,         description: "OWASP ZAP vulnerability scan" },
  { id: "normalize", label: "Normalize",       icon: <GitCompare className="h-5 w-5" />,  description: "Merge & deduplicate findings" },
  { id: "analyze",   label: "AI Analysis",     icon: <Brain className="h-5 w-5" />,       description: "GPT-4o risk scoring & triage" },
  { id: "compare",   label: "Compare",         icon: <BarChart3 className="h-5 w-5" />,   description: "AI vs traditional ranking" },
  { id: "report",    label: "Report",          icon: <FileText className="h-5 w-5" />,    description: "Generate PDF report" },
];

interface LogEntry {
  ts: string;
  phase: ScanPhase;
  message: string;
  type: "info" | "success" | "error" | "warning" | "detail" | "metric";
}

/* ───────────────────────── helpers ───────────────────────── */

function now() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 } as Intl.DateTimeFormatOptions);
}

function formatPieLabel({ name, percent }: { name?: string; percent?: number }) {
  return `${name ?? ""} ${((percent ?? 0) * 100).toFixed(0)}%`;
}

/* ───────────────────────── small components ───────────────────────── */

function SeverityBadge({ severity }: { severity: string }) {
  const c: Record<string, string> = {
    critical:      "bg-red-100 text-red-700 ring-red-600/20",
    high:          "bg-orange-100 text-orange-700 ring-orange-600/20",
    medium:        "bg-yellow-100 text-yellow-700 ring-yellow-600/20",
    low:           "bg-green-100 text-green-700 ring-green-600/20",
    informational: "bg-slate-100 text-slate-600 ring-slate-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold capitalize ring-1 ring-inset ${c[severity] ?? c.informational}`}>
      {severity}
    </span>
  );
}

function MetricCard({ label, value, sub, icon, color, bgColor }: {
  label: string; value: string | number; sub?: string; icon: React.ReactNode; color: string; bgColor: string;
}) {
  return (
    <div className="rounded-xl border bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
          <p className={`mt-1.5 text-2xl font-bold ${color}`}>{value}</p>
          {sub && <p className="mt-0.5 text-xs text-slate-400">{sub}</p>}
        </div>
        <div className={`rounded-lg p-2.5 ${bgColor}`}>{icon}</div>
      </div>
    </div>
  );
}

function StepperItem({ step, current, completedSteps, errorStep }: {
  step: PipelineStep; current: ScanPhase; completedSteps: Set<string>; errorStep: string | null;
}) {
  const isActive  = current === step.id;
  const isDone    = completedSteps.has(step.id);
  const isError   = errorStep === step.id;

  return (
    <div className={`flex items-center gap-3 rounded-lg px-4 py-3 transition-all ${
      isActive ? "bg-blue-50 ring-2 ring-blue-500" :
      isDone   ? "bg-green-50" :
      isError  ? "bg-red-50 ring-2 ring-red-400" :
                 "bg-slate-50"
    }`}>
      <div className={`flex items-center justify-center h-9 w-9 rounded-full shrink-0 ${
        isActive ? "bg-blue-500 text-white animate-pulse" :
        isDone   ? "bg-green-500 text-white" :
        isError  ? "bg-red-500 text-white" :
                   "bg-slate-200 text-slate-400"
      }`}>
        {isDone   ? <CheckCircle2 className="h-5 w-5" /> :
         isError  ? <XCircle className="h-5 w-5" /> :
         isActive ? <Loader2 className="h-5 w-5 animate-spin" /> :
                    step.icon}
      </div>
      <div className="min-w-0">
        <p className={`text-sm font-semibold truncate ${
          isActive ? "text-blue-700" :
          isDone   ? "text-green-700" :
          isError  ? "text-red-700" :
                     "text-slate-400"
        }`}>{step.label}</p>
        <p className={`text-xs truncate ${
          isActive ? "text-blue-500" :
          isDone   ? "text-green-500" :
          isError  ? "text-red-500" :
                     "text-slate-300"
        }`}>{step.description}</p>
      </div>
    </div>
  );
}

function LogFeed({ logs, currentPhase }: { logs: LogEntry[]; currentPhase: ScanPhase }) {
  const endRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Smooth auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (endRef.current) {
      endRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [logs.length]);

  const typeColors: Record<string, string> = {
    info:    "text-blue-400",
    success: "text-emerald-400",
    error:   "text-red-400",
    warning: "text-amber-400",
    detail:  "text-slate-400",
    metric:  "text-cyan-400",
  };

  const isRunningPhase = (phase: string) =>
    !["idle", "complete", "error"].includes(currentPhase) && phase === currentPhase;

  const getIcon = (type: string, phase: string) => {
    if (type === "info" && isRunningPhase(phase)) return <Loader2 className="h-3 w-3 animate-spin" />;
    if (type === "info") return <CheckCircle2 className="h-3 w-3 text-slate-500" />;
    if (type === "success") return <CheckCircle2 className="h-3 w-3" />;
    if (type === "error") return <XCircle className="h-3 w-3" />;
    if (type === "warning") return <AlertTriangle className="h-3 w-3" />;
    if (type === "detail") return <ChevronDown className="h-3 w-3 opacity-50" />;
    if (type === "metric") return <TrendingUp className="h-3 w-3" />;
    return null;
  };

  const phaseLabels: Record<string, string> = {
    nmap: "NMAP", zap: "ZAP", normalize: "NORM", analyze: "AI", compare: "CMP", report: "RPT", complete: "DONE",
  };

  const phaseColors: Record<string, string> = {
    nmap: "text-sky-500", zap: "text-orange-500", normalize: "text-violet-500",
    analyze: "text-purple-500", compare: "text-indigo-500", report: "text-teal-500", complete: "text-emerald-500",
  };

  return (
    <div className="rounded-xl border border-slate-700/50 bg-[#0d1117] text-slate-200 shadow-lg overflow-hidden">
      {/* Terminal title bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 bg-[#161b22] border-b border-slate-700/50">
        <div className="flex gap-1.5">
          <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
          <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
          <span className="h-3 w-3 rounded-full bg-[#28c840]" />
        </div>
        <span className="text-xs font-mono text-slate-500 ml-2">Pipeline Log — Live Feed</span>
        <div className="ml-auto flex items-center gap-2">
          {logs.length > 0 && (
            <span className="text-[10px] font-mono text-slate-600">{logs.length} events</span>
          )}
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
        </div>
      </div>

      {/* Log content */}
      <div
        ref={containerRef}
        className="max-h-72 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed space-y-0.5 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent"
      >
        {logs.length === 0 && (
          <div className="flex items-center gap-2 text-slate-600 py-4">
            <span className="inline-block h-2 w-2 rounded-full bg-slate-700 animate-pulse" />
            <span>Waiting for scan to start...</span>
          </div>
        )}
        {logs.map((l, i) => {
          const isPhaseHeader = l.type === "info" && (
            l.message.startsWith("Starting") || l.message.startsWith("Merging") ||
            l.message.startsWith("Sending") || l.message.startsWith("Running") ||
            l.message.startsWith("Generating") || l.message.startsWith("Initiating")
          );
          const isDone = l.type === "success";
          const isDetail = l.type === "detail";
          const isMetric = l.type === "metric";

          return (
            <div
              key={i}
              className={`flex items-start gap-2 rounded px-2 py-0.5 transition-all duration-300 animate-in fade-in slide-in-from-bottom-1 ${
                isPhaseHeader ? "mt-2 mb-0.5 bg-slate-800/60 py-1.5" :
                isDone ? "bg-emerald-950/20 border-l-2 border-emerald-600 pl-3" :
                l.type === "error" ? "bg-red-950/20 border-l-2 border-red-600 pl-3" :
                isMetric ? "bg-cyan-950/10 pl-6" :
                isDetail ? "pl-6 opacity-80" :
                ""
              }`}
            >
              <span className="text-slate-600 shrink-0 select-none w-[82px]">{l.ts}</span>
              <span className={`shrink-0 w-[36px] text-right font-bold text-[10px] ${phaseColors[l.phase] ?? "text-slate-500"}`}>
                {phaseLabels[l.phase] ?? "SYS"}
              </span>
              <span className={`shrink-0 mt-0.5 ${typeColors[l.type]}`}>{getIcon(l.type, l.phase)}</span>
              <span className={`${typeColors[l.type]} ${isPhaseHeader ? "font-semibold" : ""} ${isDetail ? "text-slate-500" : ""}`}>
                {l.message}
              </span>
            </div>
          );
        })}
        <div ref={endRef} />
      </div>
    </div>
  );
}

function VulnExpandedRow({ v }: { v: Vulnerability }) {
  return (
    <tr>
      <td colSpan={9} className="px-4 py-4 bg-slate-50 border-b border-slate-200">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <h4 className="font-semibold text-slate-700 mb-1">Description</h4>
            <p className="text-slate-600 leading-relaxed">{v.description || "No description available."}</p>
          </div>
          {v.ai_analysis && (
            <div className="space-y-2">
              <h4 className="font-semibold text-slate-700">AI Analysis</h4>
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg bg-white p-2.5 border">
                  <p className="text-xs text-slate-500">Exploitability</p>
                  <p className="font-bold text-slate-800">{v.ai_analysis.exploitability_score.toFixed(1)}/10</p>
                </div>
                <div className="rounded-lg bg-white p-2.5 border">
                  <p className="text-xs text-slate-500">Business Impact</p>
                  <p className="font-bold text-slate-800 capitalize">{v.ai_analysis.business_impact}</p>
                </div>
                <div className="rounded-lg bg-white p-2.5 border">
                  <p className="text-xs text-slate-500">False Positive Prob.</p>
                  <p className="font-bold text-slate-800">{(v.ai_analysis.false_positive_probability * 100).toFixed(0)}%</p>
                </div>
                <div className="rounded-lg bg-white p-2.5 border">
                  <p className="text-xs text-slate-500">Priority Rank</p>
                  <p className="font-bold text-slate-800">#{v.ai_analysis.priority_rank}</p>
                </div>
              </div>
              {v.ai_analysis.remediation && (
                <div className="rounded-lg bg-white p-2.5 border">
                  <p className="text-xs text-slate-500 mb-0.5">Remediation</p>
                  <p className="text-slate-700 text-xs leading-relaxed">{v.ai_analysis.remediation}</p>
                </div>
              )}
            </div>
          )}
          {v.references && v.references.length > 0 && (
            <div className="md:col-span-2">
              <h4 className="font-semibold text-slate-700 mb-1">References</h4>
              <div className="flex flex-wrap gap-2">
                {v.references.map((r, i) => {
                  let hostname = r;
                  try { hostname = new URL(r).hostname; } catch { /* use raw */ }
                  return (
                    <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                       className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline">
                      {hostname} <ExternalLink className="h-3 w-3" />
                    </a>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

/* ───────────────────────── session persistence ───────────────────────── */

const STORAGE_KEY = "dashboard_state";

interface PersistedState {
  target: string;
  currentPhase: ScanPhase;
  completedSteps: string[];
  errorStep: string | null;
  error: string | null;
  logs: LogEntry[];
  metrics: Metrics | null;
  vulnerabilities: Vulnerability[];
  reportPath: string | null;
  elapsed: string | null;
}

/* ======================================================================= */
/* MAIN PAGE                                                                */
/* ======================================================================= */

export default function DashboardPage() {
  const [target, setTarget] = useState("");
  const [currentPhase, setCurrentPhase] = useState<ScanPhase>("idle");
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());
  const [errorStep, setErrorStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [reportPath, setReportPath] = useState<string | null>(null);

  const [elapsed, setElapsed] = useState<string | null>(null);

  // Table state
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const logRef = useRef<LogEntry[]>([]);
  const phaseRef = useRef<ScanPhase>("idle");
  const restoredRef = useRef(false);

  // Restore persisted state from sessionStorage AFTER hydration (client only)
  useEffect(() => {
    if (restoredRef.current) return;
    restoredRef.current = true;
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw) as Partial<PersistedState>;
      if (saved.target) setTarget(saved.target);
      if (saved.currentPhase) setCurrentPhase(saved.currentPhase);
      if (saved.completedSteps) setCompletedSteps(new Set(saved.completedSteps));
      if (saved.errorStep !== undefined) setErrorStep(saved.errorStep);
      if (saved.error !== undefined) setError(saved.error);
      if (saved.logs) { logRef.current = saved.logs; setLogs(saved.logs); }
      if (saved.metrics) setMetrics(saved.metrics);
      if (saved.vulnerabilities) setVulnerabilities(saved.vulnerabilities);
      if (saved.reportPath !== undefined) setReportPath(saved.reportPath);
      if (saved.elapsed !== undefined) setElapsed(saved.elapsed);
      if (saved.currentPhase) phaseRef.current = saved.currentPhase;
    } catch { /* ignore corrupt storage */ }
  }, []);

  // Persist key state to sessionStorage so navigation doesn't lose results
  useEffect(() => {
    const state: PersistedState = {
      target,
      currentPhase,
      completedSteps: Array.from(completedSteps),
      errorStep,
      error,
      logs,
      metrics,
      vulnerabilities,
      reportPath,
      elapsed,
    };
    try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch { /* quota */ }
  }, [target, currentPhase, completedSteps, errorStep, error, logs, metrics, vulnerabilities, reportPath, elapsed]);

  const addLog = useCallback((phase: ScanPhase, message: string, type: LogEntry["type"] = "info") => {
    const entry: LogEntry = { ts: now(), phase, message, type };
    logRef.current = [...logRef.current, entry];
    setLogs([...logRef.current]);
  }, []);

  const markDone = useCallback((phase: ScanPhase) => {
    setCompletedSteps(prev => { const n = new Set(prev); n.add(phase); return n; });
  }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
    setPage(1);
  };

  /* -- Main scan handler -- */
  const handleScan = useCallback(async () => {
    if (!target.trim()) { setError("Please enter a target domain or IP address."); return; }

    setError(null);
    setErrorStep(null);
    setCompletedSteps(new Set());
    setMetrics(null);
    setVulnerabilities([]);
    setReportPath(null);
    logRef.current = [];
    setLogs([]);
    const t0 = Date.now();
    setElapsed(null);

    const timerRef = setInterval(() => {
      setElapsed(`${((Date.now() - t0) / 1000).toFixed(1)}s`);
    }, 200);

    const elapsedStr = () => `${((Date.now() - t0) / 1000).toFixed(1)}s`;

    // Helper: add a log then yield to the event loop so each line renders individually
    const tick = (phase: ScanPhase, msg: string, type: LogEntry["type"] = "info", delayMs = 80) =>
      new Promise<void>(resolve => {
        addLog(phase, msg, type);
        setTimeout(resolve, delayMs);
      });

    try {
      // Step 1 - Nmap
      const nmapT0 = Date.now();
      phaseRef.current = "nmap";
      setCurrentPhase("nmap");
      await tick("nmap", `Initiating Nmap network scan on target: ${target.trim()}`);
      await tick("nmap", `Resolving hostname and probing top-25 common ports (21,22,80,443,8080,...)`, "detail");
      await tick("nmap", `TCP connect scan with service detection and banner grabbing enabled`, "detail");
      const nmapRes = await startNmapScan(target.trim()) as Record<string, unknown>;
      const nmapHosts = (nmapRes?.hosts as Array<Record<string, unknown>>)?.length ?? 0;
      const nmapOpenPorts = ((nmapRes?.hosts as Array<Record<string, unknown>>)?.[0] as Record<string, unknown>)?.ports as Array<Record<string, unknown>> ?? [];
      const openCount = nmapOpenPorts.filter((p: Record<string, unknown>) => p.state === "open").length;
      const nmapDur = ((Date.now() - nmapT0) / 1000).toFixed(1);
      await tick("nmap", `Discovered ${nmapHosts} host(s) with ${openCount} open port(s) in ${nmapDur}s`, "success");
      for (const p of nmapOpenPorts.filter((p: Record<string, unknown>) => p.state === "open")) {
        const svc = (p.service as string) || "unknown";
        const ver = (p.version as string) || "";
        await tick("nmap", `  ✦ Port ${p.port}/${p.protocol} — ${svc}${ver ? ` (${ver})` : ""}`, "detail", 60);
      }
      await tick("nmap", `Scan data saved to data/raw/nmap/`, "detail", 50);
      markDone("nmap");

      // Step 2 - ZAP
      const zapT0 = Date.now();
      phaseRef.current = "zap";
      setCurrentPhase("zap");
      const zapTarget = target.trim().startsWith("http") ? target.trim() : `http://${target.trim()}`;
      await tick("zap", `Initiating OWASP ZAP web application scan on ${zapTarget}`);
      await tick("zap", `Checking security headers, cookie flags, TLS config, sensitive files...`, "detail");
      const zapRes = await startZapScan(zapTarget) as Record<string, unknown>;
      const zapVulns = (zapRes?.vulnerabilities as Array<Record<string, unknown>>) ?? [];
      const zapDur = ((Date.now() - zapT0) / 1000).toFixed(1);
      await tick("zap", `Web scan complete — ${zapVulns.length} vulnerability/ies found in ${zapDur}s`, "success");
      if (zapVulns.length > 0) {
        const sevCounts: Record<string, number> = {};
        zapVulns.forEach((v: Record<string, unknown>) => {
          const s = ((v.risk as string) || (v.severity as string) || "info").toLowerCase();
          sevCounts[s] = (sevCounts[s] || 0) + 1;
        });
        const sevStr = Object.entries(sevCounts).map(([k, v]) => `${v} ${k}`).join(", ");
        await tick("zap", `  Severity breakdown: ${sevStr}`, "metric");
        for (const v of zapVulns.slice(0, 5)) {
          const name = (v.name as string) || (v.title as string) || "Unknown finding";
          const risk = (v.risk as string) || (v.severity as string) || "info";
          await tick("zap", `  ✦ [${risk.toUpperCase()}] ${name}`, "detail", 60);
        }
        if (zapVulns.length > 5) {
          await tick("zap", `  ... and ${zapVulns.length - 5} more findings`, "detail", 40);
        }
      }
      await tick("zap", `Scan data saved to data/raw/zap/`, "detail", 50);
      markDone("zap");

      // Step 3 - Normalize
      const normT0 = Date.now();
      phaseRef.current = "normalize";
      setCurrentPhase("normalize");
      await tick("normalize", `Merging and deduplicating findings from Nmap + ZAP`);
      await tick("normalize", `Generating deterministic UUIDs, mapping severity → CVSS, deduplicating...`, "detail");
      const normRes = await runNormalize();
      const normDur = ((Date.now() - normT0) / 1000).toFixed(1);
      await tick("normalize", `Normalized ${normRes.total_vulnerabilities} unique vulnerabilities in ${normDur}s`, "success");
      const srcCounts: Record<string, number> = {};
      (normRes.vulnerabilities ?? []).forEach(v => { srcCounts[v.source] = (srcCounts[v.source] || 0) + 1; });
      if (Object.keys(srcCounts).length > 0) {
        const srcStr = Object.entries(srcCounts).map(([k, v]) => `${v} from ${k}`).join(", ");
        await tick("normalize", `  Sources: ${srcStr}`, "metric", 60);
      }
      const normSevCounts: Record<string, number> = {};
      (normRes.vulnerabilities ?? []).forEach(v => {
        const s = (v.severity || "informational").toLowerCase();
        normSevCounts[s] = (normSevCounts[s] || 0) + 1;
      });
      const normSevStr = Object.entries(normSevCounts).map(([k, v]) => `${v} ${k}`).join(", ");
      await tick("normalize", `  Severities: ${normSevStr}`, "metric", 60);
      await tick("normalize", `Output saved to data/processed/`, "detail", 50);
      markDone("normalize");

      // Step 4 - AI Analysis
      const aiT0 = Date.now();
      phaseRef.current = "analyze";
      setCurrentPhase("analyze");
      await tick("analyze", `Sending ${normRes.total_vulnerabilities} vulnerabilities to GPT-4o for AI analysis`);
      await tick("analyze", `Requesting: risk scoring, exploitability, business impact, remediation, false positive detection`, "detail");
      await tick("analyze", `Processing in chunks of 10 vulnerabilities per API call...`, "detail");
      const aiRes = await runAnalyze();
      const aiDur = ((Date.now() - aiT0) / 1000).toFixed(1);
      setVulnerabilities(aiRes.vulnerabilities);
      const aiTokens = (aiRes as unknown as Record<string, unknown> & { metrics?: { total_tokens?: number } })?.metrics?.total_tokens;
      await tick("analyze", `AI analysis complete — ${aiRes.total_vulnerabilities} vulnerabilities enriched in ${aiDur}s`, "success");
      if (aiTokens) {
        await tick("analyze", `  Tokens used: ${aiTokens.toLocaleString()} (model: GPT-4o)`, "metric", 60);
      }
      const ranked = [...(aiRes.vulnerabilities || [])].filter(v => v.ai_analysis).sort((a, b) => (a.ai_analysis?.priority_rank ?? 999) - (b.ai_analysis?.priority_rank ?? 999));
      for (let ri = 0; ri < Math.min(3, ranked.length); ri++) {
        const v = ranked[ri];
        const score = v.ai_analysis?.ai_risk_score?.toFixed(1) ?? "?";
        const impact = v.ai_analysis?.business_impact ?? "unknown";
        await tick("analyze", `  #${ri + 1} priority: ${v.title} (AI score: ${score}, impact: ${impact})`, "detail", 80);
      }
      const fpCount = (aiRes.vulnerabilities || []).filter(v => v.ai_analysis && v.ai_analysis.false_positive_probability > 0.5).length;
      if (fpCount > 0) {
        await tick("analyze", `  ⚠ ${fpCount} probable false positive(s) detected by AI`, "warning");
      }
      markDone("analyze");

      // Step 5 - Compare
      const cmpT0 = Date.now();
      phaseRef.current = "compare";
      setCurrentPhase("compare");
      await tick("compare", `Running AI vs traditional CVSS ranking comparison`);
      await tick("compare", `Computing Kendall's τ correlation, rank divergence, NDCG@10, Average Precision...`, "detail");
      const compMetrics = await runCompare();
      const cmpDur = ((Date.now() - cmpT0) / 1000).toFixed(1);
      setMetrics(compMetrics);
      await tick("compare", `Comparison complete in ${cmpDur}s`, "success");
      await tick("compare", `  Kendall's τ = ${compMetrics.kendall_tau.toFixed(3)} (${compMetrics.kendall_tau_interpretation})`, "metric", 70);
      await tick("compare", `  Divergent rankings: ${compMetrics.divergent_rankings_count} (${compMetrics.divergent_rankings_percent.toFixed(1)}%)`, "metric", 70);
      await tick("compare", `  Time saved: ${compMetrics.time_saved_percent.toFixed(1)}% (${Math.round(compMetrics.time_saved_seconds)}s)`, "metric", 70);
      await tick("compare", `  False positives: ${compMetrics.false_positives_detected_count} detected, ${compMetrics.false_positives_probable_count} probable`, "metric", 70);
      await tick("compare", `Metrics saved to data/processed/metrics.json`, "detail", 50);
      markDone("compare");

      // Step 6 - Report
      const rptT0 = Date.now();
      phaseRef.current = "report";
      setCurrentPhase("report");
      await tick("report", `Generating comprehensive PDF penetration testing report`);
      await tick("report", `Including: executive summary, vulnerability details, AI analysis, comparison metrics...`, "detail");
      const report = await generateReport();
      const rptDur = ((Date.now() - rptT0) / 1000).toFixed(1);
      setReportPath(report.report_path);
      await tick("report", `PDF report generated in ${rptDur}s`, "success");
      await tick("report", `  Output: ${report.report_path}`, "detail", 50);
      markDone("report");

      // Done
      phaseRef.current = "complete";
      setCurrentPhase("complete");
      await tick("complete" as ScanPhase, `━━━ Pipeline complete ━━━ Total time: ${elapsedStr()} | ${aiRes.total_vulnerabilities} vulns | Report ready ✓`, "success", 0);
    } catch (err) {
      setErrorStep(phaseRef.current);
      addLog(phaseRef.current, `✘ Error: ${err instanceof Error ? err.message : "Unexpected error"}`, "error");
      addLog(phaseRef.current, `Pipeline halted at ${elapsedStr()} — check logs above for details`, "warning");
      setCurrentPhase("error");
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    } finally {
      clearInterval(timerRef);
      setElapsed(`${((Date.now() - t0) / 1000).toFixed(1)}s`);
    }
  }, [target, addLog, markDone]);

  /* -- Filtered + sorted vulnerabilities -- */
  const filtered = vulnerabilities
    .filter(v => severityFilter === "all" || v.severity === severityFilter)
    .filter(v => !search ||
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.affected_asset.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity")       cmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
      else if (sortKey === "cvss_score") cmp = a.cvss_score - b.cvss_score;
      else if (sortKey === "ai_score")   cmp = (a.ai_analysis?.ai_risk_score ?? 0) - (b.ai_analysis?.ai_risk_score ?? 0);
      else if (sortKey === "ai_rank")    cmp = (a.ai_analysis?.priority_rank ?? 999) - (b.ai_analysis?.priority_rank ?? 999);
      else if (sortKey === "title")      cmp = a.title.localeCompare(b.title);
      else if (sortKey === "confidence") cmp = a.confidence.localeCompare(b.confidence);
      else if (sortKey === "source")     cmp = a.source.localeCompare(b.source);
      else if (sortKey === "affected_asset") cmp = a.affected_asset.localeCompare(b.affected_asset);
      return sortDir === "asc" ? cmp : -cmp;
    });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  /* -- Chart data -- */
  const severityChartData = metrics
    ? Object.entries(metrics.severity_distribution).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1), count: value,
        fill: SEVERITY_COLORS[name] ?? "#64748b",
      }))
    : [];

  const aiVsCvssData = (metrics?.ranking_comparison ?? []).slice(0, 15).map(r => ({
    name: r.title.substring(0, 18) + (r.title.length > 18 ? "..." : ""),
    cvss: r.cvss_score, ai: r.ai_risk_score,
  }));

  const sourceData = (() => {
    const counts: Record<string, number> = {};
    vulnerabilities.forEach(v => { counts[v.source] = (counts[v.source] ?? 0) + 1; });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  })();

  const radarData = metrics ? [
    { metric: "Kendall tau", value: Math.abs(metrics.kendall_tau) * 10, fullMark: 10 },
    { metric: "Time Saved %", value: metrics.time_saved_percent / 10, fullMark: 10 },
    { metric: "Divergence %", value: metrics.divergent_rankings_percent / 10, fullMark: 10 },
    { metric: "Avg AI Score", value: metrics.avg_ai_risk_score, fullMark: 10 },
    { metric: "Avg CVSS", value: metrics.avg_cvss_score, fullMark: 10 },
  ] : [];

  const isRunning = !["idle", "complete", "error"].includes(currentPhase);
  const SortIcon = ({ col }: { col: SortKey }) => sortKey === col ? (sortDir === "asc" ? " ↑" : " ↓") : " ⇅";
  const th = "px-3 py-2.5 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-800 whitespace-nowrap select-none";

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">

      {/* ======= Section 1: Scan Control ======= */}
      <div className="rounded-xl border bg-white shadow-sm p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-100 p-2.5">
              <Target className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-800">Scan Control Panel</h2>
              <p className="text-xs text-slate-400">Run the full AI-assisted penetration testing pipeline</p>
            </div>
          </div>
          {elapsed && (
            <div className="flex items-center gap-1.5 text-sm text-slate-500">
              <Timer className="h-4 w-4" />
              <span className="font-mono">{elapsed}</span>
            </div>
          )}
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Enter target (e.g. 192.168.1.1 or https://example.com)"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !isRunning && handleScan()}
            disabled={isRunning}
            className="flex-1 rounded-lg border border-slate-300 px-4 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <button
            onClick={handleScan}
            disabled={isRunning}
            className="flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-8 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50 transition-colors shadow-sm"
          >
            {isRunning ? (
              <><Loader2 className="h-4 w-4 animate-spin" /> Running...</>
            ) : (
              <><Shield className="h-4 w-4" /> Start Full Scan</>
            )}
          </button>
        </div>

        {error && (
          <div className="mt-3 rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span className="flex-1">{error}</span>
            <button onClick={() => setError(null)} className="ml-2 text-red-500 hover:text-red-700 font-semibold">✕</button>
          </div>
        )}
      </div>

      {/* ======= Section 2: Pipeline Progress Stepper ======= */}
      {currentPhase !== "idle" && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {PIPELINE_STEPS.map(step => (
              <StepperItem key={step.id} step={step} current={currentPhase} completedSteps={completedSteps} errorStep={errorStep} />
            ))}
          </div>

          {/* Progress bar */}
          <div className="rounded-full h-2.5 bg-slate-200 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                currentPhase === "error" ? "bg-red-500" : currentPhase === "complete" ? "bg-green-500" : "bg-blue-500"
              }`}
              style={{ width: `${(completedSteps.size / PIPELINE_STEPS.length) * 100}%` }}
            />
          </div>

          {/* Live log terminal */}
          <LogFeed logs={logs} currentPhase={currentPhase} />
        </div>
      )}

      {/* ======= Section 3: Metric Cards ======= */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <MetricCard
            label="Total Vulnerabilities"
            value={metrics.total_vulnerabilities}
            icon={<Bug className="h-5 w-5 text-blue-600" />}
            color="text-blue-700"
            bgColor="bg-blue-50"
          />
          <MetricCard
            label="Critical / High"
            value={`${metrics.severity_distribution.critical} / ${metrics.severity_distribution.high}`}
            sub={`${metrics.severity_distribution.medium} medium, ${metrics.severity_distribution.low} low`}
            icon={<ShieldAlert className="h-5 w-5 text-red-600" />}
            color="text-red-700"
            bgColor="bg-red-50"
          />
          <MetricCard
            label="Kendall tau"
            value={metrics.kendall_tau.toFixed(3)}
            sub={metrics.kendall_tau_interpretation}
            icon={<TrendingUp className="h-5 w-5 text-indigo-600" />}
            color="text-indigo-700"
            bgColor="bg-indigo-50"
          />
          <MetricCard
            label="Time Saved"
            value={`${metrics.time_saved_percent.toFixed(1)}%`}
            sub={`${Math.round(metrics.time_saved_seconds)}s faster`}
            icon={<Clock className="h-5 w-5 text-green-600" />}
            color="text-green-700"
            bgColor="bg-green-50"
          />
          <MetricCard
            label="False Positives"
            value={metrics.false_positives_detected_count}
            sub={`${metrics.false_positives_probable_count} probable`}
            icon={<ShieldCheck className="h-5 w-5 text-amber-600" />}
            color="text-amber-700"
            bgColor="bg-amber-50"
          />
        </div>
      )}

      {/* ======= Section 4: Vulnerability Table ======= */}
      {vulnerabilities.length > 0 && (
        <div className="rounded-xl border bg-white shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-5 border-b border-slate-100">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-purple-100 p-2">
                <Bug className="h-4 w-4 text-purple-600" />
              </div>
              <h2 className="text-lg font-semibold text-slate-800">
                Vulnerabilities <span className="text-sm font-normal text-slate-400">({filtered.length})</span>
              </h2>
            </div>
            <div className="flex flex-wrap gap-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="search"
                  placeholder="Search..."
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPage(1); }}
                  className="rounded-lg border border-slate-300 pl-9 pr-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-48"
                />
              </div>
              <select
                value={severityFilter}
                onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Info</option>
              </select>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-200 bg-slate-50/50">
                <tr>
                  <th className="w-8" />
                  <th className={th} onClick={() => handleSort("title")}>Title<SortIcon col="title" /></th>
                  <th className={th} onClick={() => handleSort("severity")}>Severity<SortIcon col="severity" /></th>
                  <th className={th} onClick={() => handleSort("cvss_score")}>CVSS<SortIcon col="cvss_score" /></th>
                  <th className={th} onClick={() => handleSort("ai_score")}>AI Score<SortIcon col="ai_score" /></th>
                  <th className={th} onClick={() => handleSort("ai_rank")}>AI Rank<SortIcon col="ai_rank" /></th>
                  <th className={th} onClick={() => handleSort("confidence")}>Confidence<SortIcon col="confidence" /></th>
                  <th className={th} onClick={() => handleSort("source")}>Source<SortIcon col="source" /></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {paginated.map(v => (
                  <React.Fragment key={v.id}>
                    <tr className="hover:bg-slate-50/80 cursor-pointer transition-colors" onClick={() => setExpandedId(expandedId === v.id ? null : v.id)}>
                      <td className="pl-3 py-2">
                        {expandedId === v.id
                          ? <ChevronUp className="h-4 w-4 text-slate-400" />
                          : <ChevronDown className="h-4 w-4 text-slate-400" />}
                      </td>
                      <td className="px-3 py-2.5 font-medium text-slate-800 max-w-xs truncate" title={v.title}>{v.title}</td>
                      <td className="px-3 py-2.5"><SeverityBadge severity={v.severity} /></td>
                      <td className="px-3 py-2.5 font-mono text-slate-600">{v.cvss_score.toFixed(1)}</td>
                      <td className="px-3 py-2.5 font-mono text-slate-600">{v.ai_analysis?.ai_risk_score?.toFixed(1) ?? "—"}</td>
                      <td className="px-3 py-2.5 font-mono text-slate-600">{v.ai_analysis?.priority_rank ?? "—"}</td>
                      <td className="px-3 py-2.5 capitalize text-slate-600">{v.confidence}</td>
                      <td className="px-3 py-2.5 text-slate-600">{v.source}</td>
                    </tr>
                    {expandedId === v.id && <VulnExpandedRow v={v} />}
                  </React.Fragment>
                ))}
                {paginated.length === 0 && (
                  <tr><td colSpan={9} className="px-3 py-10 text-center text-slate-400">No vulnerabilities match your filters.</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-sm text-slate-600 p-4 border-t border-slate-100">
              <span>Page {page} of {totalPages} ({filtered.length} results)</span>
              <div className="flex gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="rounded px-3 py-1 border border-slate-300 disabled:opacity-40 hover:bg-slate-50">Previous</button>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                  className="rounded px-3 py-1 border border-slate-300 disabled:opacity-40 hover:bg-slate-50">Next</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ======= Section 5: Charts ======= */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Distribution */}
          <div className="rounded-xl border bg-white shadow-sm p-6">
            <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-slate-400" /> Severity Distribution
            </h3>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={severityChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {severityChartData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* AI vs CVSS */}
          {aiVsCvssData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                <Brain className="h-4 w-4 text-purple-500" /> AI Risk Score vs CVSS
              </h3>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={aiVsCvssData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 9 }} interval={0} angle={-20} textAnchor="end" height={50} />
                  <YAxis tick={{ fontSize: 12 }} domain={[0, 10]} />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="cvss" name="CVSS" fill="#3b82f6" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="ai" name="AI Score" fill="#8b5cf6" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Source Pie */}
          {sourceData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                <RadarIcon className="h-4 w-4 text-blue-500" /> Findings by Source
              </h3>
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie data={sourceData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} label={formatPieLabel} paddingAngle={3}>
                    {sourceData.map((_, idx) => (
                      <Cell key={idx} fill={["#3b82f6", "#8b5cf6", "#22c55e", "#f97316"][idx % 4]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Radar overview */}
          {radarData.length > 0 && (
            <div className="rounded-xl border bg-white shadow-sm p-6">
              <h3 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-indigo-500" /> Analysis Overview
              </h3>
              <ResponsiveContainer width="100%" height={240}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#e2e8f0" />
                  <PolarAngleAxis dataKey="metric" tick={{ fontSize: 11 }} />
                  <PolarRadiusAxis tick={{ fontSize: 10 }} domain={[0, 10]} />
                  <Radar name="Metrics" dataKey="value" stroke="#6366f1" fill="#6366f1" fillOpacity={0.2} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* ======= Section 6: AI vs Traditional Summary ======= */}
      {metrics && (
        <div className="rounded-xl border bg-white shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-800 mb-4 flex items-center gap-2">
            <Brain className="h-5 w-5 text-indigo-500" /> AI vs Traditional Analysis
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-5">
            <div className="rounded-lg bg-indigo-50 p-4">
              <p className="text-xs text-indigo-600 font-medium">Kendall&apos;s τ</p>
              <p className="text-xl font-bold text-indigo-700">{metrics.kendall_tau.toFixed(3)}</p>
              <p className="text-xs text-indigo-500 mt-0.5">{metrics.kendall_tau_interpretation}</p>
            </div>
            <div className="rounded-lg bg-blue-50 p-4">
              <p className="text-xs text-blue-600 font-medium">Avg CVSS</p>
              <p className="text-xl font-bold text-blue-700">{metrics.avg_cvss_score.toFixed(2)}</p>
            </div>
            <div className="rounded-lg bg-purple-50 p-4">
              <p className="text-xs text-purple-600 font-medium">Avg AI Score</p>
              <p className="text-xl font-bold text-purple-700">{metrics.avg_ai_risk_score.toFixed(2)}</p>
            </div>
            <div className="rounded-lg bg-red-50 p-4">
              <p className="text-xs text-red-600 font-medium">False Positives</p>
              <p className="text-xl font-bold text-red-700">{metrics.false_positives_detected_count}</p>
              <p className="text-xs text-red-500 mt-0.5">{metrics.false_positives_probable_count} probable</p>
            </div>
            <div className="rounded-lg bg-green-50 p-4">
              <p className="text-xs text-green-600 font-medium">Time Saved</p>
              <p className="text-xl font-bold text-green-700">{metrics.time_saved_percent.toFixed(1)}%</p>
              <p className="text-xs text-green-500 mt-0.5">{Math.round(metrics.time_saved_seconds)}s</p>
            </div>
          </div>
          <p className="text-sm text-slate-500 leading-relaxed">
            The AI pipeline ranked <strong>{metrics.divergent_rankings_count}</strong> vulnerabilities differently from traditional CVSS ordering
            ({metrics.divergent_rankings_percent.toFixed(1)}% divergence), using <strong>{metrics.ai_model}</strong>.
            Kendall&apos;s τ of <strong>{metrics.kendall_tau.toFixed(3)}</strong> indicates <em>{metrics.kendall_tau_interpretation.toLowerCase()}</em>.
            Total AI tokens: {metrics.ai_tokens_used.toLocaleString()}.
          </p>
        </div>
      )}

      {/* ======= Section 7: Report Download ======= */}
      {currentPhase === "complete" && reportPath && (
        <div className="rounded-xl border bg-gradient-to-r from-green-50 to-emerald-50 shadow-sm p-6">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-green-100 p-2.5">
                <FileText className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-green-800">Report Ready</h2>
                <p className="text-xs text-green-600">Pipeline completed successfully</p>
              </div>
            </div>
            <a
              href={`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000"}/api/report/download?path=${encodeURIComponent(reportPath)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 rounded-lg bg-green-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-green-700 transition-colors shadow-sm"
            >
              <FileText className="h-4 w-4" /> Download PDF Report
            </a>
          </div>
        </div>
      )}

      {/* ======= Empty / idle state ======= */}
      {currentPhase === "idle" && (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-16 text-center">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-slate-100 flex items-center justify-center mb-4">
            <Shield className="h-8 w-8 text-slate-300" />
          </div>
          <h3 className="text-lg font-semibold text-slate-600 mb-1">No Scan Running</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Enter a target IP or domain above and click <strong>Start Full Scan</strong> to run the complete
            AI-assisted penetration testing pipeline with detailed progress tracking.
          </p>
        </div>
      )}
    </div>
  );
}
