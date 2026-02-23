/**
 * services/api.ts
 *
 * Centralised API service layer. All fetch calls to the Express backend go
 * through this module, keeping components free of HTTP concerns.
 *
 * Backend base URL is read from NEXT_PUBLIC_API_URL (defaults to localhost:3000).
 */

import type {
  HealthResponse,
  Metrics,
  PipelineResponse,
  Report,
  VulnerabilitiesResponse,
} from "@/types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

// ---------------------------------------------------------------------------
// Generic fetch wrapper with error handling
// ---------------------------------------------------------------------------
async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      message = body.error || message;
    } catch {
      // ignore parse errors
    }
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
export async function checkHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/health");
}

// ---------------------------------------------------------------------------
// Start a full pipeline scan (normalize → analyze → compare → report)
// Returns live results after the pipeline completes.
// ---------------------------------------------------------------------------
export async function startPipeline(): Promise<PipelineResponse> {
  return apiFetch<PipelineResponse>("/api/pipeline", { method: "POST" });
}

// ---------------------------------------------------------------------------
// Start Nmap scan
// ---------------------------------------------------------------------------
export async function startNmapScan(
  target: string,
  ports = "1-1024",
  args = "-sV -O"
): Promise<unknown> {
  return apiFetch("/api/scan/nmap", {
    method: "POST",
    body: JSON.stringify({ target, ports, args }),
  });
}

// ---------------------------------------------------------------------------
// Start ZAP scan
// ---------------------------------------------------------------------------
export async function startZapScan(targetUrl: string): Promise<unknown> {
  return apiFetch("/api/scan/zap", {
    method: "POST",
    body: JSON.stringify({ target_url: targetUrl }),
  });
}

// ---------------------------------------------------------------------------
// Run normalization step
// ---------------------------------------------------------------------------
export async function runNormalize(): Promise<VulnerabilitiesResponse> {
  return apiFetch<VulnerabilitiesResponse>("/api/normalize", {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Run AI analysis step
// ---------------------------------------------------------------------------
export async function runAnalyze(): Promise<VulnerabilitiesResponse> {
  return apiFetch<VulnerabilitiesResponse>("/api/analyze", {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Run comparison step
// ---------------------------------------------------------------------------
export async function runCompare(): Promise<Metrics> {
  return apiFetch<Metrics>("/api/compare", { method: "POST" });
}

// ---------------------------------------------------------------------------
// Generate PDF report
// ---------------------------------------------------------------------------
export async function generateReport(): Promise<Report> {
  return apiFetch<Report>("/api/report", { method: "POST" });
}

// ---------------------------------------------------------------------------
// Get latest vulnerabilities
// ---------------------------------------------------------------------------
export async function getVulnerabilities(): Promise<VulnerabilitiesResponse> {
  return apiFetch<VulnerabilitiesResponse>("/api/vulnerabilities");
}

// ---------------------------------------------------------------------------
// Get latest comparison metrics
// ---------------------------------------------------------------------------
export async function getMetrics(): Promise<Metrics> {
  return apiFetch<Metrics>("/api/metrics");
}
