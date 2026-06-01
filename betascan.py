#!/usr/bin/env python3
"""
BetaScan - asynchronous TCP port scanner with service detection and fingerprinting.

Usage:
  python betascan.py <target> --ports 1-1024,8080 --timeout 1.5 --workers 200
  python betascan.py <target> --top 100 --format json --open-only
"""

from __future__ import annotations
import argparse
import asyncio
import sys
import subprocess
from typing import Sequence

# 1. Manage File Descriptors safely
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except (ValueError, OSError):
            pass
except ImportError:
    pass

from config import TOP_PORT_PRESETS, DEFAULT_READ_TIMEOUT
from database import init_cve_cache
from core.scanner import (
    parse_ports, scan_target, render_table_output, render_json_output, 
    render_csv_output, write_output, format_summary, SCAPY_AVAILABLE
)
from core.script_engine import load_dynamic_scripts

def manage_iptables_rule(action="insert"):
    """Automate Iptables ruling to handle kernel RSTs when using Scapy."""
    cmd = ["iptables", "-I" if action == "insert" else "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP port scanner with service detection, vulnerability mapping, and advanced stealth features."
    )
    parser.add_argument("target", help="IP address, domain name, or CIDR (e.g. 192.168.1.0/24)")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("--ports", help="Port range list (e.g., 1-1024,8080)")
    port_group.add_argument("--top", choices=sorted(TOP_PORT_PRESETS.keys()), help="Use curated common ports list (20, 50, or 100)")
    
    # Advanced Scan Types
    scan_group = parser.add_argument_group("Advanced Scan Techniques")
    scan_group.add_argument("-sT", "--tcp-connect", action="store_true", help="TCP Connect Scan (Default)")
    scan_group.add_argument("-sS", "--stealth-syn", action="store_true", help="SYN Stealth Scan (Requires Scapy/Root)")
    scan_group.add_argument("-sU", "--udp-scan", action="store_true", help="UDP Scan (Requires Scapy/Root)")
    scan_group.add_argument("-sF", "--fin-scan", action="store_true", help="FIN Scan (Requires Scapy/Root)")
    scan_group.add_argument("-sX", "--xmas-scan", action="store_true", help="Xmas Scan (Requires Scapy/Root)")
    scan_group.add_argument("-sN", "--null-scan", action="store_true", help="Null Scan (Requires Scapy/Root)")

    # Performance
    perf_group = parser.add_argument_group("Performance & Timing")
    perf_group.add_argument("-T", "--timing", type=int, choices=[0, 1, 2, 3, 4, 5], help="Timing template (higher is faster: 0-5)")
    perf_group.add_argument("--timeout", type=float, default=1.5, help="Connection timeout in seconds")
    perf_group.add_argument("--read-timeout", type=float, default=DEFAULT_READ_TIMEOUT, help="Read timeout for banners and probes")
    perf_group.add_argument("--workers", type=int, default=200, help="Number of concurrent workers")
    perf_group.add_argument("--retries", type=int, default=2, help="Retry attempts for timeouts")
    perf_group.add_argument("--backoff", type=float, default=0.2, help="Delay between retries in seconds")
    perf_group.add_argument("--rate", type=float, default=0.0, help="Limit new connections per second (0 = unlimited)")

    # Recognition and Vulns
    vuln_group = parser.add_argument_group("Service Detection & Vulnerabilities")
    vuln_group.add_argument("-O", "--os", action="store_true", help="Attempt OS Fingerprinting")
    vuln_group.add_argument("--cve", action="store_true", help="Lookup CVEs for detected services")
    vuln_group.add_argument("--script", help="Run a specific custom script/engine (e.g. vuln_check)")

    # Evasion
    evas_group = parser.add_argument_group("Firewall/IDS Evasion")
    evas_group.add_argument("-D", "--decoy", help="Comma-separated list of decoy IP addresses (requires Scapy)")
    evas_group.add_argument("--spoof-mac", help="Spoof MAC address (requires Scapy)")
    evas_group.add_argument("-f", "--fragment", action="store_true", help="Fragment packets (requires Scapy)")

    # General Options
    parser.add_argument("--open-only", action="store_true", help="Show only open ports")
    parser.add_argument("--fingerprint", action=argparse.BooleanOptionalAction, default=True, help="Enable or disable service fingerprinting")
    parser.add_argument("--tls", action=argparse.BooleanOptionalAction, default=True, help="Enable or disable TLS probing for HTTPS ports")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--output", "-o", help="Write output to a file instead of stdout")
    parser.set_defaults(ports="1-1024")
    
    return parser.parse_args(argv)

def validate_args(args: argparse.Namespace) -> None:
    if args.timing is not None:
        if args.timing == 0:
            args.timeout, args.workers, args.retries, args.backoff = 3.0, 10, 3, 1.0
        elif args.timing == 1:
            args.timeout, args.workers, args.retries, args.backoff = 2.0, 50, 3, 0.5
        elif args.timing == 2:
            args.timeout, args.workers, args.retries, args.backoff = 1.5, 100, 2, 0.2
        elif args.timing == 3:
            args.timeout, args.workers, args.retries, args.backoff = 1.0, 200, 2, 0.1
        elif args.timing == 4:
            args.timeout, args.workers, args.retries, args.backoff = 0.5, 500, 1, 0.05
        elif args.timing == 5:
            args.timeout, args.workers, args.retries, args.backoff = 0.2, 1000, 0, 0.0

    needs_scapy = any([args.stealth_syn, args.udp_scan, args.fin_scan, args.xmas_scan, args.null_scan, args.decoy, args.spoof_mac, args.fragment, args.os])
    if needs_scapy and not SCAPY_AVAILABLE:
        raise ValueError("Advanced scanning features, OS detection, and evasion require 'scapy' library and root privileges.")

    if args.timeout <= 0: raise ValueError("Timeout must be positive.")
    if args.read_timeout <= 0: raise ValueError("Read timeout must be positive.")
    if args.workers <= 0: raise ValueError("Workers must be positive.")
    if args.retries < 0: raise ValueError("Retries must be zero or positive.")
    if args.backoff < 0: raise ValueError("Backoff must be zero or positive.")
    if args.rate < 0: raise ValueError("Rate must be zero or positive.")

def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        ports = TOP_PORT_PRESETS[args.top] if args.top else parse_ports(args.ports)
        validate_args(args)
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    # Initialize SQL Cache safely
    if args.cve:
        init_cve_cache()

    dyn_scripts = load_dynamic_scripts()

    scan_type = "TCP"
    if args.stealth_syn: scan_type = "SYN"
    elif args.udp_scan: scan_type = "UDP"
    elif args.fin_scan: scan_type = "FIN"
    elif args.xmas_scan: scan_type = "XMAS"
    elif args.null_scan: scan_type = "NULL"

    reports = []
    
    try:
        if scan_type == "SYN":
            manage_iptables_rule("insert")
            
        asyncio.run(
            scan_target(
                args.target, ports, args.timeout, args.workers, args.retries, args.tls, args.fingerprint, 
                args.read_timeout, args.backoff, args.rate, args.open_only,
                reports_list=reports, scan_type=scan_type, do_os=args.os, do_cve=args.cve, script_name=args.script, 
                decoy=args.decoy, spoof_mac=args.spoof_mac, fragment=args.fragment, dynamic_scripts=dyn_scripts
            )
        )
    except KeyboardInterrupt:
        print("\n[info] Scan interrupted by user. Generating partial report gracefully...", file=sys.stderr)
    finally:
        # Assure iptables cleanup on exit/interruption
        if scan_type == "SYN":
            manage_iptables_rule("delete")

    if not reports:
        return 0

    if args.format == "table":
        content = render_table_output(reports)
        write_output(content, args.output)
    elif args.format == "json":
        content = render_json_output(reports)
        write_output(content, args.output)
    elif args.format == "csv":
        content = render_csv_output(reports)
        write_output(content, args.output)

    if args.format in {"json", "csv"}:
        for report in reports:
            print(format_summary(report), file=sys.stderr)

    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))