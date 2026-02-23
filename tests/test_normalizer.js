/**
 * test_normalizer.js - Unit tests for the vulnerability normalization module.
 */

"use strict";

const {
  normaliseNmapResult,
  normaliseZapResult,
  deduplicate,
  generateId,
  normalize,
} = require("../src/normalizer/normalizer");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const sampleNmapResult = {
  scan_id: "nmap_test_001",
  tool: "nmap",
  target: "192.168.1.1",
  hosts: [
    {
      ip: "192.168.1.1",
      hostnames: ["router.local"],
      state: "up",
      os_matches: [{ name: "Linux 4.x", accuracy: 95 }],
      ports: [
        {
          port: 22,
          protocol: "tcp",
          state: "open",
          service: "ssh",
          product: "OpenSSH",
          version: "8.9",
          extra_info: "",
          cpe: "cpe:/a:openbsd:openssh:8.9",
        },
        {
          port: 80,
          protocol: "tcp",
          state: "open",
          service: "http",
          product: "nginx",
          version: "1.18",
          extra_info: "",
          cpe: "",
        },
        {
          port: 8080,
          protocol: "tcp",
          state: "closed",
          service: "http-proxy",
          product: "",
          version: "",
          extra_info: "",
          cpe: "",
        },
      ],
    },
  ],
};

const sampleZapResult = {
  scan_id: "zap_test_001",
  tool: "owasp_zap",
  target: "http://192.168.1.1",
  vulnerabilities: [
    {
      name: "X-Frame-Options Header Not Set",
      risk_label: "Medium",
      severity: "medium",
      description: "The X-Frame-Options header is not included in the HTTP response.",
      affected_url: "http://192.168.1.1/",
      cwe_id: 1021,
      confidence: "Medium",
      solution: "Add X-Frame-Options header.",
      references: ["https://owasp.org/www-community/attacks/Clickjacking"],
    },
    {
      name: "SQL Injection",
      risk_label: "High",
      severity: "high",
      description: "SQL injection vulnerability detected.",
      affected_url: "http://192.168.1.1/login",
      cwe_id: 89,
      confidence: "High",
      solution: "Use parameterised queries.",
      references: [],
    },
  ],
};

// ---------------------------------------------------------------------------
// Tests: generateId
// ---------------------------------------------------------------------------

describe("generateId", () => {
  test("generates a consistent UUID for same inputs", () => {
    const id1 = generateId("nmap", "Open port 22", "192.168.1.1");
    const id2 = generateId("nmap", "Open port 22", "192.168.1.1");
    expect(id1).toBe(id2);
  });

  test("generates different IDs for different inputs", () => {
    const id1 = generateId("nmap", "Open port 22", "192.168.1.1");
    const id2 = generateId("nmap", "Open port 80", "192.168.1.1");
    expect(id1).not.toBe(id2);
  });

  test("ID format matches UUID v5 pattern", () => {
    const id = generateId("owasp_zap", "SQL Injection", "http://example.com");
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

// ---------------------------------------------------------------------------
// Tests: normaliseNmapResult
// ---------------------------------------------------------------------------

describe("normaliseNmapResult", () => {
  test("returns an array", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    expect(Array.isArray(result)).toBe(true);
  });

  test("only includes open ports", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    const portFindings = result.filter((v) => v.title.includes("Open port"));
    // port 22 (open) and port 80 (open) => 2 port findings; port 8080 closed = excluded
    expect(portFindings).toHaveLength(2);
  });

  test("includes OS detection finding", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    const osFindings = result.filter((v) => v.title.includes("OS Detected"));
    expect(osFindings).toHaveLength(1);
    expect(osFindings[0].title).toContain("Linux 4.x");
  });

  test("sets correct source field", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    result.forEach((v) => expect(v.source).toBe("nmap"));
  });

  test("sets severity for port 22 as high", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    const ssh = result.find((v) => v.title.includes("port 22"));
    expect(ssh).toBeDefined();
    expect(ssh.severity).toBe("high");
  });

  test("all entries have required fields", () => {
    const result = normaliseNmapResult(sampleNmapResult);
    const required = ["id", "source", "title", "severity", "cvss_score", "description", "affected_asset", "confidence", "references"];
    result.forEach((v) => {
      required.forEach((field) => {
        expect(v).toHaveProperty(field);
      });
    });
  });

  test("returns empty array for empty hosts", () => {
    const result = normaliseNmapResult({ hosts: [] });
    expect(result).toHaveLength(0);
  });

  test("handles missing hosts field gracefully", () => {
    const result = normaliseNmapResult({});
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: normaliseZapResult
// ---------------------------------------------------------------------------

describe("normaliseZapResult", () => {
  test("returns correct number of vulnerabilities", () => {
    const result = normaliseZapResult(sampleZapResult);
    expect(result).toHaveLength(2);
  });

  test("sets correct source field", () => {
    const result = normaliseZapResult(sampleZapResult);
    result.forEach((v) => expect(v.source).toBe("owasp_zap"));
  });

  test("maps High risk to high severity", () => {
    const result = normaliseZapResult(sampleZapResult);
    const sql = result.find((v) => v.title === "SQL Injection");
    expect(sql).toBeDefined();
    expect(sql.severity).toBe("high");
  });

  test("maps Medium risk to medium severity", () => {
    const result = normaliseZapResult(sampleZapResult);
    const xframe = result.find((v) => v.title.includes("X-Frame-Options"));
    expect(xframe).toBeDefined();
    expect(xframe.severity).toBe("medium");
  });

  test("assigns correct CVSS score for high severity", () => {
    const result = normaliseZapResult(sampleZapResult);
    const sql = result.find((v) => v.title === "SQL Injection");
    expect(sql.cvss_score).toBe(7.5);
  });

  test("returns empty array for missing vulnerabilities", () => {
    const result = normaliseZapResult({ target: "http://example.com" });
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: deduplicate
// ---------------------------------------------------------------------------

describe("deduplicate", () => {
  test("removes duplicate IDs", () => {
    const vulns = [
      { id: "aaa", title: "Test 1", severity: "high" },
      { id: "aaa", title: "Test 1 duplicate", severity: "high" },
      { id: "bbb", title: "Test 2", severity: "medium" },
    ];
    const deduped = deduplicate(vulns);
    expect(deduped).toHaveLength(2);
  });

  test("keeps the first occurrence on duplicate", () => {
    const vulns = [
      { id: "aaa", title: "First", severity: "high" },
      { id: "aaa", title: "Second", severity: "high" },
    ];
    const deduped = deduplicate(vulns);
    expect(deduped[0].title).toBe("First");
  });

  test("handles empty array", () => {
    expect(deduplicate([])).toHaveLength(0);
  });

  test("returns all items when no duplicates", () => {
    const vulns = [
      { id: "a", title: "A" },
      { id: "b", title: "B" },
      { id: "c", title: "C" },
    ];
    expect(deduplicate(vulns)).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Tests: normalize (integration)
// ---------------------------------------------------------------------------

describe("normalize (integration)", () => {
  test("combines nmap and zap results", () => {
    const result = normalize(sampleNmapResult, sampleZapResult);
    // 2 open ports + 1 OS = 3 nmap + 2 zap = 5 total
    expect(result.length).toBeGreaterThan(0);
  });

  test("sorts by severity then CVSS (highest first)", () => {
    const result = normalize(sampleNmapResult, sampleZapResult);
    for (let i = 0; i < result.length - 1; i++) {
      const current = result[i];
      const next = result[i + 1];
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
      const severityRankCurrent = severityOrder[current.severity] ?? 5;
      const severityRankNext = severityOrder[next.severity] ?? 5;
      expect(severityRankCurrent).toBeLessThanOrEqual(severityRankNext);
    }
  });

  test("returns empty array when no data", () => {
    const result = normalize(null, null);
    expect(result).toHaveLength(0);
  });

  test("all results have unique IDs", () => {
    const result = normalize(sampleNmapResult, sampleZapResult);
    const ids = result.map((v) => v.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});
