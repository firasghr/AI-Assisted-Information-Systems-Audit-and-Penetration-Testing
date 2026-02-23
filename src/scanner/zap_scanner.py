"""
zap_scanner.py - OWASP ZAP active scan module.

What is OWASP ZAP?
    The Zed Attack Proxy (ZAP) is one of the world's most popular free
    security testing tools maintained by OWASP. It acts as a man-in-the-middle
    proxy between a browser and a web application, passively and actively
    looking for security vulnerabilities. ZAP automates many techniques that
    a manual tester would perform, including:
    - Injection attacks (SQL, LDAP, command injection)
    - Cross-Site Scripting (XSS)
    - Broken authentication and session management
    - Security misconfiguration
    - Insecure direct object references

How this fits into traditional pentesting:
    In the PTES (Penetration Testing Execution Standard) and OWASP Testing
    Guide, web application testing follows the reconnaissance and scanning
    phases. ZAP automates the "exploitation" and "vulnerability identification"
    steps for web applications, which traditionally required manual testing
    with tools like Burp Suite or manual HTTP request manipulation.
    This module represents the traditional automated web-scan workflow before
    AI-assisted prioritisation is applied downstream.

Output:
    Normalised vulnerability objects are stored as JSON in data/raw/zap/
    using the same envelope format as the Nmap scanner for consistency.

Improvements suggested:
    - Add authenticated scan support (session token injection).
    - Integrate passive scan results alongside active scan.
    - Add Ajax Spider for Single-Page Application (SPA) coverage.
    - Correlate ZAP CWE IDs with NVD CVSS scores automatically.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import requests
from zapv2 import ZAPv2  # python-owasp-zap-v2.4

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("zap_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw", "zap")
os.makedirs(OUTPUT_DIR, exist_ok=True)

POLL_INTERVAL_SECONDS = 5  # How often to check scan progress
MAX_WAIT_SECONDS = 3600     # Abort if scan takes longer than 1 hour


# ---------------------------------------------------------------------------
# Severity mapping: ZAP risk strings -> normalised severity
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    "High":          "high",
    "Medium":        "medium",
    "Low":           "low",
    "Informational": "informational",
}


# ---------------------------------------------------------------------------
# Normalise a single ZAP alert into the project's unified format
# ---------------------------------------------------------------------------
def _normalise_alert(alert: dict) -> dict:
    """
    Convert a raw ZAP alert dict into the project's intermediate vulnerability
    format.

    Args:
        alert: Raw alert dict returned by the ZAP API.

    Returns:
        Normalised vulnerability dictionary.
    """
    risk_label = alert.get("risk", "Informational")
    severity = SEVERITY_MAP.get(risk_label, "informational")

    # CWE ID may be an empty string; convert to None for consistency
    raw_cwe = alert.get("cweid", "")
    cwe_id = int(raw_cwe) if raw_cwe and raw_cwe.isdigit() else None

    # References come as a newline-delimited string
    raw_refs = alert.get("reference", "")
    references = [r.strip() for r in raw_refs.splitlines() if r.strip()]

    return {
        "name": alert.get("alert", ""),
        "severity": severity,
        "risk_label": risk_label,
        "description": alert.get("description", ""),
        "affected_url": alert.get("url", ""),
        "cwe_id": cwe_id,
        "confidence": alert.get("confidence", ""),
        "solution": alert.get("solution", ""),
        "references": references,
        "plugin_id": alert.get("pluginId", ""),
        "evidence": alert.get("evidence", ""),
        "attack": alert.get("attack", ""),
        "param": alert.get("param", ""),
        "other": alert.get("other", ""),
    }


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------
def scan(
    target_url: str,
    zap_base_url: str = "http://localhost:8080",
    api_key: str = "",
) -> dict:
    """
    Connect to a running ZAP daemon, spider and actively scan *target_url*,
    then return normalised vulnerability results.

    Prerequisites:
        ZAP must be running in daemon mode:
        $ zap.sh -daemon -port 8080 -config api.key=<YOUR_KEY>

    Args:
        target_url:   The URL of the web application to test.
        zap_base_url: Base URL of the ZAP API daemon (default: localhost:8080).
        api_key:      ZAP API key (leave empty if API key auth is disabled).

    Returns:
        Dictionary with scan metadata and normalised vulnerability list.

    Raises:
        ValueError: If target_url is empty.
        requests.exceptions.ConnectionError: If ZAP daemon is unreachable.
        TimeoutError: If scan does not complete within MAX_WAIT_SECONDS.
    """
    if not target_url or not target_url.strip():
        raise ValueError("target_url must be a non-empty string")

    target_url = target_url.strip()
    logger.info("Connecting to ZAP at %s | target=%s", zap_base_url, target_url)

    zap = ZAPv2(apikey=api_key, proxies={"http": zap_base_url, "https": zap_base_url})

    # Verify connectivity before starting
    try:
        zap_version = zap.core.version
        logger.info("ZAP version: %s", zap_version)
    except Exception as exc:
        logger.error("Cannot connect to ZAP daemon at %s: %s", zap_base_url, exc)
        raise requests.exceptions.ConnectionError(
            f"ZAP daemon unreachable at {zap_base_url}"
        ) from exc

    start_time = time.time()

    # -----------------------------------------------------------------------
    # Phase 1: Spider the target to discover URLs
    # -----------------------------------------------------------------------
    logger.info("Starting spider scan...")
    spider_id = zap.spider.scan(target_url, apikey=api_key)
    logger.info("Spider scan ID: %s", spider_id)

    while int(zap.spider.status(spider_id)) < 100:
        elapsed = time.time() - start_time
        if elapsed > MAX_WAIT_SECONDS:
            raise TimeoutError(f"Spider scan timed out after {MAX_WAIT_SECONDS}s")
        progress = zap.spider.status(spider_id)
        logger.info("Spider progress: %s%%", progress)
        time.sleep(POLL_INTERVAL_SECONDS)

    logger.info("Spider scan completed. URLs found: %d", len(zap.spider.results(spider_id)))

    # -----------------------------------------------------------------------
    # Phase 2: Active scan
    # -----------------------------------------------------------------------
    logger.info("Starting active scan...")
    scan_id = zap.ascan.scan(target_url, apikey=api_key)
    logger.info("Active scan ID: %s", scan_id)

    while int(zap.ascan.status(scan_id)) < 100:
        elapsed = time.time() - start_time
        if elapsed > MAX_WAIT_SECONDS:
            raise TimeoutError(f"Active scan timed out after {MAX_WAIT_SECONDS}s")
        progress = zap.ascan.status(scan_id)
        logger.info("Active scan progress: %s%%", progress)
        time.sleep(POLL_INTERVAL_SECONDS)

    elapsed = round(time.time() - start_time, 2)
    logger.info("Active scan completed in %.2fs", elapsed)

    # -----------------------------------------------------------------------
    # Phase 3: Retrieve and normalise alerts
    # -----------------------------------------------------------------------
    raw_alerts = zap.core.alerts(baseurl=target_url)
    vulnerabilities = [_normalise_alert(a) for a in raw_alerts]

    # Deduplicate by (name, affected_url) — ZAP can report the same alert
    # at the same URL multiple times from different scan rules
    seen = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v["name"], v["affected_url"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    logger.info(
        "Alerts retrieved: %d total, %d unique",
        len(vulnerabilities),
        len(unique_vulns),
    )

    result = {
        "scan_id": f"zap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "tool": "owasp_zap",
        "target": target_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_time_seconds": elapsed,
        "total_alerts": len(vulnerabilities),
        "unique_vulnerabilities": len(unique_vulns),
        "vulnerabilities": unique_vulns,
    }

    # Persist to disk
    filename = (
        f"{result['scan_id']}_{target_url.replace('://', '_').replace('/', '_')}.json"
    )
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    logger.info("Results saved to %s", filepath)
    return result


# ---------------------------------------------------------------------------
# Entry point (CLI usage)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run an OWASP ZAP active scan and save structured JSON output."
    )
    parser.add_argument("target_url", help="URL of the web application to test")
    parser.add_argument(
        "--zap-url",
        default=os.environ.get("ZAP_BASE_URL", "http://localhost:8080"),
        help="ZAP daemon base URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ZAP_API_KEY", ""),
        help="ZAP API key",
    )
    args = parser.parse_args()

    output = scan(args.target_url, zap_base_url=args.zap_url, api_key=args.api_key)
    print(json.dumps(output, indent=2))
