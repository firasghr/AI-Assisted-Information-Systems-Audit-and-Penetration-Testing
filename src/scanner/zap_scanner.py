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

    # Quick connectivity check with a short timeout — prevents the ZAPv2
    # proxy call from hanging forever when ZAP daemon is not running.
    try:
        probe_url = f"{zap_base_url}/JSON/core/view/version/"
        resp = requests.get(probe_url, timeout=5)
        resp.raise_for_status()
        logger.info("ZAP daemon reachable (version probe OK)")
    except Exception as exc:
        logger.warning("Cannot connect to ZAP daemon at %s: %s. Falling back to HTTP header scan.", zap_base_url, exc)
        # -----------------------------------------------------------------
        # Fallback: real HTTP-based security header & response analysis.
        # Actually fetches the target and checks for missing security
        # headers, cookie flags, server info leakage, TLS issues, etc.
        # Produces genuine, target-specific results.
        # -----------------------------------------------------------------
        start_time = time.time()

        unique_vulns = []
        checked_urls = set()

        def check_url(url):
            """Fetch a URL and generate real vulnerability findings."""
            if url in checked_urls:
                return
            checked_urls.add(url)

            try:
                resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            except requests.exceptions.SSLError as ssl_err:
                unique_vulns.append({
                    "name": "SSL/TLS Certificate Error",
                    "severity": "high",
                    "risk_label": "High",
                    "cwe_id": 295,
                    "affected_url": url,
                    "confidence": "High",
                    "description": f"SSL/TLS connection failed: {str(ssl_err)[:200]}. The server's certificate could not be validated, indicating a potential man-in-the-middle risk or misconfigured TLS.",
                    "solution": "Install a valid TLS certificate from a trusted Certificate Authority. Ensure the certificate chain is complete and not expired.",
                    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
                    "plugin_id": "fb-tls-01",
                    "evidence": str(ssl_err)[:150],
                    "attack": "", "param": "", "other": "",
                })
                try:
                    resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                except Exception:
                    return
            except requests.exceptions.ConnectionError:
                logger.warning("Cannot reach %s — skipping", url)
                return
            except Exception as e:
                logger.warning("Error fetching %s: %s", url, e)
                return

            headers = {k.lower(): v for k, v in resp.headers.items()}
            server = headers.get("server", "")

            # --- Missing security headers ---
            security_headers = {
                "content-security-policy": {
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "severity": "medium", "risk_label": "Medium", "cwe_id": 693,
                    "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. The CSP header was not found in the response.",
                    "solution": "Ensure the web server sets the Content-Security-Policy header with an appropriate policy for the application.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                },
                "x-content-type-options": {
                    "name": "X-Content-Type-Options Header Missing",
                    "severity": "low", "risk_label": "Low", "cwe_id": 693,
                    "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of browsers to MIME-sniff the response body, potentially causing the response body to be interpreted as a different content type.",
                    "solution": "Set the X-Content-Type-Options header to 'nosniff' for all responses.",
                    "references": ["https://owasp.org/www-community/Security_Headers"],
                },
                "x-frame-options": {
                    "name": "X-Frame-Options Header Not Set (Clickjacking)",
                    "severity": "medium", "risk_label": "Medium", "cwe_id": 1021,
                    "description": "X-Frame-Options header is not included in the HTTP response, allowing the page to be framed by malicious sites. This can lead to clickjacking attacks where users are tricked into clicking elements on a transparent overlay.",
                    "solution": "Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN', or use CSP frame-ancestors directive.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options", "https://owasp.org/www-community/attacks/Clickjacking"],
                },
                "strict-transport-security": {
                    "name": "Strict-Transport-Security Header Missing (HSTS)",
                    "severity": "low", "risk_label": "Low", "cwe_id": 319,
                    "description": "HTTP Strict Transport Security (HSTS) header is not set. Without HSTS, the browser may allow downgrade attacks from HTTPS to HTTP, enabling man-in-the-middle attacks.",
                    "solution": "Add the Strict-Transport-Security header with an appropriate max-age value (e.g., max-age=31536000; includeSubDomains).",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                },
                "x-xss-protection": {
                    "name": "X-XSS-Protection Header Not Set",
                    "severity": "low", "risk_label": "Low", "cwe_id": 693,
                    "description": "The X-XSS-Protection header is not set. While modern browsers have deprecated this header in favor of CSP, older browsers use it to detect and block reflected XSS attacks.",
                    "solution": "Set the X-XSS-Protection header to '1; mode=block' for legacy browser support, and implement CSP as the primary XSS mitigation.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
                },
                "referrer-policy": {
                    "name": "Referrer-Policy Header Missing",
                    "severity": "informational", "risk_label": "Informational", "cwe_id": 200,
                    "description": "The Referrer-Policy header is not set. Without this header, the browser may send the full URL in the Referer header to other sites, potentially leaking sensitive path or query string information.",
                    "solution": "Set the Referrer-Policy header to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                },
                "permissions-policy": {
                    "name": "Permissions-Policy Header Missing",
                    "severity": "informational", "risk_label": "Informational", "cwe_id": 693,
                    "description": "The Permissions-Policy (formerly Feature-Policy) header is not set. This header controls which browser features (camera, microphone, geolocation, etc.) may be used.",
                    "solution": "Set the Permissions-Policy header to restrict access to sensitive browser APIs.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                },
            }

            for header_name, vuln_info in security_headers.items():
                if header_name not in headers:
                    unique_vulns.append({
                        **vuln_info,
                        "affected_url": url,
                        "confidence": "High",
                        "plugin_id": f"fb-header-{header_name[:8]}",
                        "evidence": f"Header '{header_name}' not found in response",
                        "attack": "", "param": "", "other": "",
                    })

            # --- Server information leakage ---
            if server:
                unique_vulns.append({
                    "name": f"Server Leaks Version Information via 'Server' HTTP Response Header",
                    "severity": "low", "risk_label": "Low", "cwe_id": 200,
                    "affected_url": url,
                    "confidence": "High",
                    "description": f"The server is sending the 'Server' header with value '{server}'. This reveals web server software and version, giving attackers information about potential vulnerabilities.",
                    "solution": "Configure the web server to suppress or genericize the Server header. For Apache: 'ServerTokens Prod'. For Nginx: 'server_tokens off'.",
                    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                    "plugin_id": "fb-info-01",
                    "evidence": f"Server: {server}",
                    "attack": "", "param": "", "other": "",
                })

            # --- X-Powered-By leakage ---
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                unique_vulns.append({
                    "name": f"Server Leaks Information via 'X-Powered-By' Header",
                    "severity": "low", "risk_label": "Low", "cwe_id": 200,
                    "affected_url": url,
                    "confidence": "High",
                    "description": f"The HTTP header 'X-Powered-By: {powered_by}' reveals the technology stack. Attackers can use this to find version-specific exploits.",
                    "solution": "Remove the X-Powered-By header from HTTP responses.",
                    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"],
                    "plugin_id": "fb-info-02",
                    "evidence": f"X-Powered-By: {powered_by}",
                    "attack": "", "param": "", "other": "",
                })

            # --- Cookie flags ---
            for cookie_header in resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]:
                cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
                cl = cookie_header.lower()
                if "httponly" not in cl:
                    unique_vulns.append({
                        "name": f"Cookie Without HttpOnly Flag: {cookie_name}",
                        "severity": "low", "risk_label": "Low", "cwe_id": 1004,
                        "affected_url": url,
                        "confidence": "Medium",
                        "description": f"A cookie ('{cookie_name}') was set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based cookie theft.",
                        "solution": "Set the HttpOnly flag on all cookies that do not need JavaScript access.",
                        "references": ["https://owasp.org/www-community/HttpOnly"],
                        "plugin_id": "fb-cookie-01",
                        "evidence": cookie_header[:200],
                        "attack": "", "param": "", "other": "",
                    })
                if "secure" not in cl and url.startswith("https"):
                    unique_vulns.append({
                        "name": f"Cookie Without Secure Flag: {cookie_name}",
                        "severity": "low", "risk_label": "Low", "cwe_id": 614,
                        "affected_url": url,
                        "confidence": "Medium",
                        "description": f"A cookie ('{cookie_name}') served over HTTPS was set without the Secure flag, meaning it could be sent over unencrypted HTTP connections.",
                        "solution": "Set the Secure flag on all cookies served over HTTPS.",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"],
                        "plugin_id": "fb-cookie-02",
                        "evidence": cookie_header[:200],
                        "attack": "", "param": "", "other": "",
                    })
                if "samesite" not in cl:
                    unique_vulns.append({
                        "name": f"Cookie Without SameSite Attribute: {cookie_name}",
                        "severity": "low", "risk_label": "Low", "cwe_id": 1275,
                        "affected_url": url,
                        "confidence": "Medium",
                        "description": f"A cookie ('{cookie_name}') was set without the SameSite attribute, potentially making it vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                        "solution": "Set the SameSite attribute to 'Lax' or 'Strict' on all cookies.",
                        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                        "plugin_id": "fb-cookie-03",
                        "evidence": cookie_header[:200],
                        "attack": "", "param": "", "other": "",
                    })

            # --- HTTP (no TLS) ---
            if url.startswith("http://") and not url.startswith("http://localhost"):
                unique_vulns.append({
                    "name": "Unencrypted HTTP Connection (No TLS)",
                    "severity": "medium", "risk_label": "Medium", "cwe_id": 319,
                    "affected_url": url,
                    "confidence": "High",
                    "description": "The application is served over unencrypted HTTP. All data (including credentials, session tokens, and sensitive information) is transmitted in cleartext and can be intercepted by network attackers.",
                    "solution": "Migrate to HTTPS with a valid TLS certificate. Implement HSTS and redirect all HTTP traffic to HTTPS.",
                    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
                    "plugin_id": "fb-tls-02",
                    "evidence": f"URL scheme is http://",
                    "attack": "", "param": "", "other": "",
                })

            # --- Directory-style paths to probe ---
            return resp

        # Suppress insecure request warnings for verify=False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Check main URL
        main_resp = check_url(target_url)

        # Also try HTTPS variant if HTTP was given, and vice versa
        if target_url.startswith("http://"):
            https_url = target_url.replace("http://", "https://", 1)
            check_url(https_url)
        elif target_url.startswith("https://"):
            http_url = target_url.replace("https://", "http://", 1)
            check_url(http_url)

        # Probe common paths for additional findings
        from urllib.parse import urljoin
        for probe_path in ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/wp-login.php", "/admin", "/server-status"]:
            probe_full = urljoin(target_url, probe_path)
            if probe_full in checked_urls:
                continue
            try:
                pr = requests.get(probe_full, timeout=5, allow_redirects=False, verify=False)
                if pr.status_code == 200 and probe_path in ["/.env", "/.git/config"]:
                    unique_vulns.append({
                        "name": f"Sensitive File Publicly Accessible: {probe_path}",
                        "severity": "high", "risk_label": "High", "cwe_id": 538,
                        "affected_url": probe_full,
                        "confidence": "High",
                        "description": f"The file '{probe_path}' is publicly accessible and returned HTTP 200. This file may contain sensitive configuration data, credentials, or internal information.",
                        "solution": f"Restrict access to '{probe_path}' via server configuration. Block access using .htaccess, nginx location rules, or web application firewall rules.",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                        "plugin_id": "fb-file-01",
                        "evidence": f"HTTP {pr.status_code} for {probe_path} ({len(pr.content)} bytes)",
                        "attack": "", "param": "", "other": "",
                    })
                elif pr.status_code == 200 and probe_path == "/server-status":
                    unique_vulns.append({
                        "name": "Apache Server Status Page Publicly Accessible",
                        "severity": "medium", "risk_label": "Medium", "cwe_id": 200,
                        "affected_url": probe_full,
                        "confidence": "High",
                        "description": "The Apache mod_status page is publicly accessible, exposing server performance metrics, currently connected clients, and request details.",
                        "solution": "Restrict access to /server-status to internal IP addresses only.",
                        "references": ["https://httpd.apache.org/docs/2.4/mod/mod_status.html"],
                        "plugin_id": "fb-file-02",
                        "evidence": f"HTTP {pr.status_code} ({len(pr.content)} bytes)",
                        "attack": "", "param": "", "other": "",
                    })
                # Check headers on probed URLs too
                probed_hdrs = {k.lower(): v for k, v in pr.headers.items()}
                if probe_path == "/robots.txt" and pr.status_code == 200:
                    body = pr.text
                    if "Disallow:" in body:
                        disallowed = [line.split(":", 1)[1].strip() for line in body.splitlines() if line.strip().startswith("Disallow:") and len(line.split(":", 1)) > 1 and line.split(":", 1)[1].strip()]
                        if disallowed:
                            unique_vulns.append({
                                "name": "Information Disclosure via robots.txt",
                                "severity": "informational", "risk_label": "Informational", "cwe_id": 200,
                                "affected_url": probe_full,
                                "confidence": "Medium",
                                "description": f"The robots.txt file discloses {len(disallowed)} disallowed path(s): {', '.join(disallowed[:5])}. While intended for search engines, this reveals potentially sensitive areas of the application to attackers.",
                                "solution": "Review disallowed paths to ensure no sensitive directories are listed. Consider using authentication instead of robots.txt to protect sensitive areas.",
                                "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"],
                                "plugin_id": "fb-info-03",
                                "evidence": f"Disallowed paths: {', '.join(disallowed[:5])}",
                                "attack": "", "param": "", "other": "",
                            })
            except Exception:
                pass

        # Deduplicate by (name, affected_url)
        seen = set()
        deduped = []
        for v in unique_vulns:
            key = (v["name"], v.get("affected_url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(v)

        elapsed = round(time.time() - start_time, 2)
        logger.info("HTTP header scan completed in %.2fs — %d findings", elapsed, len(deduped))

        result = {
            "scan_id": f"zap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "tool": "owasp_zap",
            "target": target_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_seconds": elapsed,
            "total_alerts": len(deduped),
            "unique_vulnerabilities": len(deduped),
            "vulnerabilities": deduped,
            "note": "ZAP daemon not reachable. Results produced via HTTP header security analysis."
        }
        
        # Persist to disk
        filename = (
            f"{result['scan_id']}_{target_url.replace('://', '_').replace('/', '_')}.json"
        )
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        
        logger.info("Scan results saved to %s", filepath)
        return result

    # ZAP is reachable — create the API client
    zap = ZAPv2(apikey=api_key, proxies={"http": zap_base_url, "https": zap_base_url})
    logger.info("ZAP version: %s", zap.core.version)

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
