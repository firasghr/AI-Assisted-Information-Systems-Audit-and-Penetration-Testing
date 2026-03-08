"""
nmap_scanner.py - Production-grade Nmap scanning module.

Traditional Pentesting Approach:
    In classical penetration testing, Nmap (Network Mapper) is the de-facto
    standard for network reconnaissance. This phase — often called "scanning
    and enumeration" — corresponds to phase 2 of the penetration testing
    methodology (after reconnaissance). The tester maps open ports, running
    services and OS fingerprints before attempting exploitation.

    This module automates that workflow, producing structured JSON output
    that feeds the normalization and AI analysis layers downstream.

Scan types performed:
    - TCP SYN scan (-sS): Half-open scan; fastest and stealthiest TCP scan.
    - Service detection (-sV): Probes open ports to identify running services.
    - Version detection (-sV): Included with service detection.
    - OS detection (-O): Fingerprints the target OS via TCP/IP stack analysis.
    - Script scan (-sC): Runs default NSE scripts for additional enumeration.

Security consideration:
    SYN scans require root/Administrator privileges and should only be run
    against hosts you are authorised to test. This module validates that the
    target is a non-empty string but does NOT perform authorisation checks —
    that is the operator's responsibility.

Output:
    Results are stored as JSON in data/raw/nmap/ with a timestamp-based
    filename to support longitudinal comparison.

Improvements suggested:
    - Add parallel scanning for multiple targets (asyncio / multiprocessing).
    - Integrate NSE vulnerability scripts (-script vuln) for CVE mapping.
    - Persist results to a database for trend analysis.
    - Implement rate-limiting and evasion options (-T parameter).
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import nmap  # python-nmap wrapper around the nmap binary
import socket
import ssl
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("nmap_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw", "nmap")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Helper: normalise a single host's data from nmap results
# ---------------------------------------------------------------------------
def _normalise_host(nm: nmap.PortScanner, host: str) -> dict:
    """
    Convert the raw nmap PortScanner dict for a single host into the
    project's unified intermediate format.

    Args:
        nm: Active nmap.PortScanner instance with scan results loaded.
        host: IP address string of the host to extract.

    Returns:
        Dictionary with normalised host data.
    """
    host_data = nm[host]
    state = host_data.state()

    # OS detection produces a list of guesses sorted by accuracy
    os_matches = []
    if "osmatch" in host_data:
        for match in host_data["osmatch"]:
            os_matches.append(
                {
                    "name": match.get("name", ""),
                    "accuracy": int(match.get("accuracy", 0)),
                }
            )

    # Enumerate all protocols (tcp, udp, etc.) and their ports
    ports = []
    for proto in host_data.all_protocols():
        for port_num in sorted(host_data[proto].keys()):
            port_info = host_data[proto][port_num]
            ports.append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extra_info": port_info.get("extrainfo", ""),
                    "cpe": port_info.get("cpe", ""),
                }
            )

    # Hostnames
    hostnames = [h["name"] for h in host_data.hostnames() if h.get("name")]

    return {
        "ip": host,
        "hostnames": hostnames,
        "state": state,
        "os_matches": os_matches,
        "ports": ports,
    }


# ---------------------------------------------------------------------------
# Main scanning function
# ---------------------------------------------------------------------------
def scan(target: str, ports: str = "1-1024", arguments: str = "-sS -sV -O -sC") -> dict:
    """
    Perform a comprehensive Nmap scan against *target* and return structured
    JSON-serialisable results.

    Args:
        target:    IP address, hostname, or CIDR range to scan.
        ports:     Port specification string (e.g. "1-1024", "80,443,8080").
        arguments: Additional nmap arguments.  Defaults to SYN + service +
                   OS + script scan.  Override with care.

    Returns:
        Dictionary with scan metadata and per-host results, suitable for
        JSON serialisation and downstream processing.

    Raises:
        ValueError: If target is empty or None.
        nmap.PortScannerError: If nmap binary is not found or scan fails.
    """
    if not target or not target.strip():
        raise ValueError("target must be a non-empty string")

    target = target.strip()
    logger.info("Starting Nmap scan | target=%s ports=%s args=%s", target, ports, arguments)

    start_time = time.time()

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments=arguments)
    except nmap.PortScannerError as exc:
        logger.warning("Nmap binary not available: %s. Falling back to socket-based scan.", exc)
        # -----------------------------------------------------------------
        # Fallback: real TCP connect scan using Python sockets
        # This actually probes the target ports and grabs service banners,
        # producing genuine per-target results without needing nmap installed.
        # -----------------------------------------------------------------

        # Resolve hostname from URL-like targets
        clean_target = target
        if "://" in clean_target:
            clean_target = urlparse(clean_target).hostname or clean_target
        clean_target = clean_target.rstrip("/")

        # Resolve IP address
        try:
            ip_addr = socket.gethostbyname(clean_target)
        except socket.gaierror:
            ip_addr = clean_target

        # Parse port range
        port_list = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                port_list.extend(range(int(lo), int(hi) + 1))
            else:
                port_list.append(int(part))

        # Common service/product mappings
        WELL_KNOWN = {
            21: ("ftp", "vsftpd", "3.0.3"),
            22: ("ssh", "OpenSSH", ""),
            23: ("telnet", "", ""),
            25: ("smtp", "Postfix", ""),
            53: ("domain", "ISC BIND", ""),
            80: ("http", "", ""),
            110: ("pop3", "", ""),
            143: ("imap", "", ""),
            443: ("https", "", ""),
            445: ("microsoft-ds", "Samba", ""),
            993: ("imaps", "", ""),
            995: ("pop3s", "", ""),
            3306: ("mysql", "MySQL", ""),
            3389: ("ms-wbt-server", "", ""),
            5432: ("postgresql", "PostgreSQL", ""),
            6379: ("redis", "Redis", ""),
            8080: ("http-proxy", "", ""),
            8443: ("https-alt", "", ""),
            27017: ("mongodb", "MongoDB", ""),
        }

        open_ports = []
        logger.info("Socket-scanning %d ports on %s (%s)...", len(port_list), clean_target, ip_addr)

        for port_num in port_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    if s.connect_ex((ip_addr, port_num)) == 0:
                        service, product, version = WELL_KNOWN.get(port_num, ("unknown", "", ""))
                        banner = ""
                        # Try to grab banner
                        try:
                            if port_num == 443 or port_num == 8443:
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                with ctx.wrap_socket(socket.socket(), server_hostname=clean_target) as ss:
                                    ss.settimeout(2)
                                    ss.connect((ip_addr, port_num))
                                    cert = ss.getpeercert(True)
                                    if cert:
                                        product = "TLS"
                                        version = ""
                            else:
                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bs:
                                    bs.settimeout(2)
                                    bs.connect((ip_addr, port_num))
                                    bs.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % clean_target.encode())
                                    banner = bs.recv(1024).decode("utf-8", errors="replace").strip()
                        except Exception:
                            pass

                        # Try to extract server/version from banner
                        if banner:
                            srv_match = re.search(r"[Ss]erver:\s*(.+)", banner)
                            if srv_match:
                                product = srv_match.group(1).split("/")[0].strip()
                                ver_parts = srv_match.group(1).split("/")
                                if len(ver_parts) > 1:
                                    version = ver_parts[1].split()[0].strip()
                            ssh_match = re.search(r"(OpenSSH[_\s][\d.]+\w*|dropbear[\d.]*)", banner, re.I)
                            if ssh_match:
                                product = "OpenSSH"
                                version = ssh_match.group(1).replace("OpenSSH_", "").replace("OpenSSH ", "")

                        open_ports.append({
                            "port": port_num,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                            "product": product,
                            "version": version,
                            "extra_info": banner[:120] if banner and not banner.startswith("HTTP") else "",
                            "cpe": "",
                        })
                        logger.info("  Port %d/tcp OPEN (%s %s)", port_num, service, product)
            except Exception:
                pass

        elapsed = round(time.time() - start_time, 2)
        logger.info("Socket scan completed in %.2fs — %d open ports found", elapsed, len(open_ports))

        result = {
            "scan_id": f"nmap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "tool": "nmap",
            "target": target,
            "ports_scanned": ports,
            "arguments": arguments,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_seconds": elapsed,
            "hosts_scanned": 1,
            "hosts": [
                {
                    "ip": ip_addr,
                    "hostnames": [clean_target] if clean_target != ip_addr else [],
                    "state": "up" if open_ports else "down",
                    "os_matches": [],
                    "ports": open_ports,
                }
            ],
            "nmap_info": {"scantype": {"fallback": "socket-connect-scan"}, "scan_time": elapsed},
            "note": "Nmap binary not found. Results produced via Python socket connect scan."
        }
        
        # Persist to disk
        filename = f"{result['scan_id']}_{target.replace('/', '_')}.json"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        
        logger.info("Scan results saved to %s", filepath)
        return result

    elapsed = round(time.time() - start_time, 2)
    logger.info("Scan completed in %.2fs | hosts_up=%d", elapsed, len(nm.all_hosts()))

    # Assemble the result envelope
    result = {
        "scan_id": f"nmap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "tool": "nmap",
        "target": target,
        "ports_scanned": ports,
        "arguments": arguments,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_time_seconds": elapsed,
        "hosts_scanned": len(nm.all_hosts()),
        "hosts": [_normalise_host(nm, h) for h in nm.all_hosts()],
        # Raw nmap info block (nmap version, command line, etc.)
        "nmap_info": nm.scaninfo(),
    }

    # Persist to disk
    filename = f"{result['scan_id']}_{target.replace('/', '_')}.json"
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
        description="Run an Nmap scan and save structured JSON output."
    )
    parser.add_argument("target", help="IP address, hostname, or CIDR range")
    parser.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument(
        "--args",
        default="-sS -sV -O -sC",
        help="Additional nmap arguments (default: -sS -sV -O -sC)",
    )
    args = parser.parse_args()

    output = scan(args.target, ports=args.ports, arguments=args.args)
    print(json.dumps(output, indent=2))
