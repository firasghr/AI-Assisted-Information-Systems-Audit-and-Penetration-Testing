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
  ScanDetail,
  ScanSummary,
  VulnerabilitiesResponse,
} from "@/types";

export const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

// ---------------------------------------------------------------------------
// Typed API error — carries the HTTP status code so callers can branch on it
// reliably without fragile string matching.
// ---------------------------------------------------------------------------
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

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
    throw new ApiError(message, response.status);
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

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

/**
 * List all past scans.
 * Calls GET /api/scans on the backend.
 * Falls back gracefully to an empty array when the endpoint returns 404
 * (scan-history store not yet implemented), so the UI still renders cleanly.
 */
export async function getScans(): Promise<ScanSummary[]> {
  try {
    return await apiFetch<ScanSummary[]>("/api/scans");
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return [];
    throw err;
  }
}

/**
 * Get the full detail for a single scan.
 * Calls GET /api/scans/:id on the backend.
 */
export async function getScanById(id: string): Promise<ScanDetail> {
  return apiFetch<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`);
}
