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
import csv
import io
import errno
import ipaddress
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


# --- Configuration and presets ---


@dataclass(frozen=True)
class PortSpec:
    service: str
    banner: bool = False
    probe: Optional[str] = None
    tls_app: Optional[str] = None


# Common ports where a plaintext HTTP probe is generally safe.
HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 7001, 9000}

PROBE_COMMANDS = {
    "ftp": "SYST\r\n",
    "smtp": "EHLO {host}\r\n",
    "imap": "a1 CAPABILITY\r\n",
    "pop3": "CAPA\r\n",
    "redis": "*1\r\n$4\r\nPING\r\n",
}

PORT_SPECS = {
    21: PortSpec("ftp", banner=True, probe="ftp"),
    22: PortSpec("ssh", banner=True),
    23: PortSpec("telnet", banner=True),
    25: PortSpec("smtp", banner=True, probe="smtp"),
    53: PortSpec("domain"),
    110: PortSpec("pop3", banner=True, probe="pop3"),
    143: PortSpec("imap", banner=True, probe="imap"),
    389: PortSpec("ldap", banner=True),
    443: PortSpec("https", tls_app="http"),
    465: PortSpec("smtps", tls_app="smtp"),
    587: PortSpec("smtp", banner=True, probe="smtp"),
    993: PortSpec("imaps", tls_app="imap"),
    995: PortSpec("pop3s", tls_app="pop3"),
    3306: PortSpec("mysql", banner=True),
    5432: PortSpec("postgresql", banner=True),
    6379: PortSpec("redis", probe="redis"),
    8443: PortSpec("https", tls_app="http"),
    9443: PortSpec("https", tls_app="http"),
}

SERVICE_HINTS = {port: spec.service for port, spec in PORT_SPECS.items()}

COMMON_PORTS = [
    int(port)
    for port in (
        "80 443 22 21 25 3389 110 445 139 23 53 3306 8080 5900 993 995 "
        "1723 111 135 143 587 465 123 161 162 389 636 1433 1521 5432 "
        "6379 2049 69 67 68 88 179 631 902 1194 5060 5061 5000 8000 "
        "8443 9000 9090 9200 27017 27018 27019 7001 7002 7003 7004 "
        "7005 8888 7070 8008 8081 8086 8090 8444 8500 8787 9100 10000 "
        "11211 20 37 49 70 79 81 82 83 84 85 89 90 99 100 106 109 113 "
        "119 194 137 138 514 515 548 554 873 989 990 1080 1701 1812 1813"
    ).split()
]

TOP_PORT_PRESETS = {
    "20": COMMON_PORTS[:20],
    "50": COMMON_PORTS[:50],
    "100": COMMON_PORTS[:100],
}

MAX_BANNER_BYTES = 2048
MAX_VERSION_LEN = 160
DEFAULT_READ_TIMEOUT = 1.0


# --- Data models ---


@dataclass(frozen=True)
class ScanResult:
    port: int
    protocol: str
    status: str
    service: str
    version: str


@dataclass(frozen=True)
class ScanReport:
    target: str
    ip: str
    results: List[ScanResult]
    summary: dict
    duration: float
    open_only: bool


@dataclass(frozen=True)
class TargetAddress:
    ip: str
    family: int


# --- Rate limiting ---


class RateLimiter:
    def __init__(self, rate_per_sec: float) -> None:
        self._interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_time = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            if self._next_time <= now:
                self._next_time = now + self._interval
                return
            delay = self._next_time - now
            self._next_time += self._interval
        if delay > 0:
            await asyncio.sleep(delay)


# --- Parsing and validation ---


def parse_ports(spec: str) -> List[int]:
    """Parse a port specification like "1-1024,8080" into a sorted list."""
    if not spec:
        raise ValueError("Port specification cannot be empty.")

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start = int(start_str)
                end = int(end_str)
            else:
                start = int(part)
                end = start
        except ValueError as exc:
            raise ValueError(f"Invalid port token: {part}") from exc

        if start != end:
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                validate_port(port)
                ports.add(port)
        else:
            validate_port(start)
            ports.add(start)

    if not ports:
        raise ValueError("No valid ports found in specification.")

    return sorted(ports)


def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range: {port}")


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    return True


def resolve_target(target: str) -> List[TargetAddress]:
    """Resolve a target to a list of IP addresses (v4/v6)."""
    try:
        ipaddress.ip_address(target)
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        return [TargetAddress(ip=target, family=family)]
    except ValueError:
        pass

    if not is_valid_hostname(target):
        raise ValueError(f"Invalid domain name: {target}")

    results: List[TargetAddress] = []
    seen = set()
    try:
        infos = socket.getaddrinfo(
            target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target: {target}") from exc

    for info in infos:
        family, _, _, _, sockaddr = info
        ip = sockaddr[0]
        if ip not in seen:
            results.append(TargetAddress(ip=ip, family=family))
            seen.add(ip)

    if not results:
        raise ValueError(f"Unable to resolve target: {target}")

    return results


# --- Service identification ---


def guess_service(port: int, banner: str) -> str:
    if port in SERVICE_HINTS:
        return SERVICE_HINTS[port]
    hint = banner_service_hint(banner)
    if hint:
        return hint
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def banner_service_hint(banner: str) -> str:
    if not banner:
        return ""
    lower = banner.lower()
    if lower.startswith("ssh-"):
        return "ssh"
    if lower.startswith("http/"):
        return "http"
    if "smtp" in lower or "esmtp" in lower:
        return "smtp"
    if lower.startswith("220") and "ftp" in lower:
        return "ftp"
    if lower.startswith("* ok"):
        return "imap"
    if lower.startswith("+ok") and "pop" in lower:
        return "pop3"
    if lower.startswith("+pong"):
        return "redis"
    if "imap" in lower:
        return "imap"
    if "pop3" in lower:
        return "pop3"
    if "mysql" in lower:
        return "mysql"
    if "postgres" in lower:
        return "postgresql"
    if "redis" in lower:
        return "redis"
    return ""


def trim_version(text: str) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= MAX_VERSION_LEN:
        return cleaned
    return cleaned[: MAX_VERSION_LEN - 3] + "..."


# --- TLS helpers ---


def build_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # Fingerprinting should not fail on self-signed or mismatched certificates.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def extract_common_name(name_entries: Sequence[Tuple[Tuple[str, str], ...]]) -> str:
    for entry in name_entries:
        for key, value in entry:
            if key.lower() == "commonname":
                return value
    return ""


def format_cert_info(cert: dict) -> str:
    if not cert:
        return ""
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    cn = extract_common_name(subject)
    issuer_cn = extract_common_name(issuer)
    sans = [
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind == "DNS"
    ]
    san_text = ""
    if sans:
        if len(sans) > 3:
            san_text = f"SAN: {', '.join(sans[:3])} (+{len(sans) - 3} more)"
        else:
            san_text = f"SAN: {', '.join(sans)}"
    parts = []
    if cn:
        parts.append(f"CN={cn}")
    if issuer_cn:
        parts.append(f"Issuer={issuer_cn}")
    if san_text:
        parts.append(san_text)
    return "; ".join(parts)


def format_tls_info(ssl_obj: Optional[ssl.SSLObject]) -> str:
    if not ssl_obj:
        return ""
    version = ssl_obj.version() or ""
    cipher = ""
    cipher_info = ssl_obj.cipher()
    if cipher_info:
        cipher = cipher_info[0] or ""
    cert_info = format_cert_info(ssl_obj.getpeercert())
    parts = ["TLS"]
    if version:
        parts.append(version)
    if cipher:
        parts.append(cipher)
    base = " ".join(parts)
    if cert_info:
        return f"{base}; {cert_info}"
    return base


# --- I/O helpers and probes ---


def join_parts(*parts: str) -> str:
    return "; ".join([part for part in parts if part])


async def read_with_timeout(
    reader: asyncio.StreamReader, timeout: float, max_bytes: int
) -> str:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    return data.decode("utf-8", errors="replace").strip()


async def write_with_timeout(
    writer: asyncio.StreamWriter, data: bytes, timeout: float
) -> bool:
    try:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False
    return True


async def send_command_and_read(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    command: str,
    timeout: float,
) -> str:
    if not await write_with_timeout(
        writer, command.encode("ascii", errors="ignore"), timeout
    ):
        return ""
    return await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)


async def command_probe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    command: str,
    host_hint: str,
    timeout: float,
    read_banner: bool,
) -> str:
    banner = (
        await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
        if read_banner
        else ""
    )
    host = host_hint if is_valid_hostname(host_hint) else "scan.local"
    command_line = command.format(host=host)
    response = await send_command_and_read(reader, writer, command_line, timeout)
    return join_parts(banner, response)


async def http_probe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    timeout: float,
) -> str:
    request = (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: BetaScan/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    if not await write_with_timeout(
        writer, request.encode("ascii", errors="ignore"), timeout
    ):
        return ""

    response = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
    if not response:
        return ""
    headers = response.split("\r\n")
    status_line = headers[0] if headers else ""
    server = ""
    powered = ""
    for header in headers[1:]:
        if header.lower().startswith("server:"):
            server = header.split(":", 1)[1].strip()
        if header.lower().startswith("x-powered-by:"):
            powered = header.split(":", 1)[1].strip()
    parts = [status_line.strip()]
    if server:
        parts.append(f"Server: {server}")
    if powered:
        parts.append(f"X-Powered-By: {powered}")
    return "; ".join([p for p in parts if p])


async def tls_app_probe(
    address: TargetAddress,
    port: int,
    host_hint: str,
    timeout: float,
    app: str,
) -> Tuple[str, str]:
    context = build_tls_context()
    try:
        reader, writer = await open_stream(
            address,
            port,
            timeout,
            ssl_context=context,
            server_hostname=host_hint,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return "", ""

    tls_info = format_tls_info(writer.get_extra_info("ssl_object"))
    banner = ""
    try:
        if app == "http":
            banner = await http_probe(reader, writer, host_hint, timeout)
        elif app in PROBE_COMMANDS:
            banner = await command_probe(
                reader,
                writer,
                PROBE_COMMANDS[app],
                host_hint,
                timeout,
                read_banner=True,
            )
        else:
            banner = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
    finally:
        await close_writer(writer)

    return banner, tls_info


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    wait_closed = getattr(writer, "wait_closed", None)
    if wait_closed:
        try:
            await wait_closed()
        except OSError:
            pass


# --- Network operations and scanning ---


def classify_os_error(exc: OSError) -> str:
    refused = {
        errno.ECONNREFUSED,
        10061,
    }
    timeouts = {
        errno.ETIMEDOUT,
        10060,
    }
    unreachable = {
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        10065,
        10051,
    }
    err = exc.errno
    win = getattr(exc, "winerror", None)
    if err in refused or win in refused:
        return "closed"
    if err in timeouts or win in timeouts:
        return "filtered"
    if err in unreachable or win in unreachable:
        return "filtered"
    return "filtered"


async def open_tcp_connection(
    address: TargetAddress, port: int, timeout: float
) -> Tuple[str, Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
    try:
        reader, writer = await open_stream(address, port, timeout)
        return "open", reader, writer
    except asyncio.TimeoutError:
        return "filtered", None, None
    except ConnectionRefusedError:
        return "closed", None, None
    except OSError as exc:
        return classify_os_error(exc), None, None


async def open_stream(
    address: TargetAddress,
    port: int,
    timeout: float,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(
        asyncio.open_connection(
            host=address.ip,
            port=port,
            family=address.family,
            ssl=ssl_context,
            server_hostname=server_hostname,
        ),
        timeout=timeout,
    )


async def fingerprint_open_port(
    address: TargetAddress,
    port: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host_hint: str,
    timeout: float,
    use_tls: bool,
    read_timeout: float,
) -> Tuple[str, str]:
    read_timeout = min(timeout, read_timeout)
    banner = ""
    tls_info = ""

    spec = PORT_SPECS.get(port)
    if spec and spec.banner:
        banner = await read_with_timeout(reader, read_timeout, MAX_BANNER_BYTES)

    if spec and spec.probe:
        probe_info = await command_probe(
            reader,
            writer,
            PROBE_COMMANDS[spec.probe],
            host_hint,
            read_timeout,
            read_banner=spec.banner and not bool(banner),
        )
        banner = join_parts(banner, probe_info)

    if not banner and port in HTTP_PORTS:
        banner = await http_probe(reader, writer, host_hint, read_timeout)

    if use_tls and spec and spec.tls_app:
        tls_banner, tls_info = await tls_app_probe(
            address, port, host_hint, read_timeout, spec.tls_app
        )
        banner = join_parts(banner, tls_banner)

    service = guess_service(port, banner)
    version = join_parts(tls_info, banner) or "-"
    return service, trim_version(version)


async def scan_port(
    address: TargetAddress,
    port: int,
    timeout: float,
    retries: int,
    host_hint: str,
    use_tls: bool,
    fingerprint: bool,
    read_timeout: float,
    backoff: float,
    limiter: Optional[RateLimiter],
) -> ScanResult:
    statuses: List[str] = []
    for attempt in range(max(1, retries)):
        if limiter:
            await limiter.wait()
        status, reader, writer = await open_tcp_connection(address, port, timeout)
        if status == "open" and reader and writer:
            service = "-"
            version = "-"
            if fingerprint:
                service, version = await fingerprint_open_port(
                    address,
                    port,
                    reader,
                    writer,
                    host_hint,
                    timeout,
                    use_tls,
                    read_timeout,
                )
            else:
                service = guess_service(port, "")
            await close_writer(writer)
            return ScanResult(
                port=port,
                protocol="tcp",
                status="open",
                service=service or "unknown",
                version=version or "-",
            )
        statuses.append(status)
        if status == "filtered" and backoff > 0 and attempt < retries - 1:
            await asyncio.sleep(backoff * (attempt + 1))

    final_status = "closed" if "closed" in statuses else "filtered"
    return ScanResult(
        port=port,
        protocol="tcp",
        status=final_status,
        service="-",
        version="-",
    )


# --- Output rendering ---


def render_table(rows: Sequence[ScanResult]) -> str:
    headers = ["Port", "Proto", "Status", "Service", "Version"]
    data = [
        [str(row.port), row.protocol, row.status, row.service, row.version]
        for row in rows
    ]
    widths = [len(h) for h in headers]
    for row in data:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def fmt_row(cells: Sequence[str]) -> str:
        parts = [cells[i].ljust(widths[i]) for i in range(len(cells))]
        return "| " + " | ".join(parts) + " |"

    sep = "+" + "+".join(["-" * (w + 2) for w in widths]) + "+"

    lines = [sep, fmt_row(headers), sep]
    for row in data:
        lines.append(fmt_row(row))
    lines.append(sep)
    return "\n".join(lines)


def build_summary(rows: Sequence[ScanResult]) -> dict:
    summary = {"open": 0, "closed": 0, "filtered": 0, "total": len(rows)}
    for row in rows:
        if row.status in summary:
            summary[row.status] += 1
    return summary


def format_summary(report: ScanReport) -> str:
    summary = report.summary
    parts = [
        f"Scanned: {summary['total']}",
        f"Open: {summary['open']}",
        f"Closed: {summary['closed']}",
        f"Filtered: {summary['filtered']}",
        f"Duration: {report.duration:.2f}s",
    ]
    if report.open_only:
        parts.append(f"Displayed: {len(report.results)}")
    return "Summary: " + ", ".join(parts)


def render_table_output(reports: Sequence[ScanReport]) -> str:
    chunks: List[str] = []
    for idx, report in enumerate(reports):
        if idx:
            chunks.append("")
        chunks.append(f"Target: {report.target} ({report.ip})")
        chunks.append(render_table(report.results))
        chunks.append(format_summary(report))
    return "\n".join(chunks)


def report_to_dict(report: ScanReport) -> dict:
    return {
        "target": report.target,
        "ip": report.ip,
        "duration_seconds": round(report.duration, 3),
        "summary": report.summary,
        "open_only": report.open_only,
        "displayed_count": len(report.results),
        "results": [
            {
                "port": row.port,
                "protocol": row.protocol,
                "status": row.status,
                "service": row.service,
                "version": row.version,
            }
            for row in report.results
        ],
    }


def render_json_output(reports: Sequence[ScanReport]) -> str:
    payload = [report_to_dict(report) for report in reports]
    return json.dumps(payload, indent=2, ensure_ascii=True)


def render_csv_output(reports: Sequence[ScanReport]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["target", "ip", "port", "protocol", "status", "service", "version"])
    for report in reports:
        for row in report.results:
            writer.writerow(
                [
                    report.target,
                    report.ip,
                    row.port,
                    row.protocol,
                    row.status,
                    row.service,
                    row.version,
                ]
            )
    return buffer.getvalue().strip("\n")


def write_output(content: str, output_path: Optional[str]) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    else:
        print(content)


# --- Scan orchestration ---


async def scan_target(
    target: str,
    ports: Iterable[int],
    timeout: float,
    workers: int,
    retries: int,
    use_tls: bool,
    fingerprint: bool,
    read_timeout: float,
    backoff: float,
    rate: float,
    open_only: bool,
) -> List[ScanReport]:
    addresses = resolve_target(target)
    host_hint = target
    reports: List[ScanReport] = []

    for address in addresses:
        results: List[ScanResult] = []
        semaphore = asyncio.Semaphore(workers)
        limiter = RateLimiter(rate) if rate > 0 else None
        start_time = time.perf_counter()

        async def bounded_scan(port: int) -> ScanResult:
            async with semaphore:
                return await scan_port(
                    address,
                    port,
                    timeout,
                    retries,
                    host_hint,
                    use_tls,
                    fingerprint,
                    read_timeout,
                    backoff,
                    limiter,
                )

        tasks = [asyncio.create_task(bounded_scan(port)) for port in ports]
        for task in asyncio.as_completed(tasks):
            results.append(await task)

        results.sort(key=lambda r: r.port)
        duration = time.perf_counter() - start_time
        summary = build_summary(results)
        display_results = (
            [row for row in results if row.status == "open"]
            if open_only
            else results
        )
        reports.append(
            ScanReport(
                target=target,
                ip=address.ip,
                results=display_results,
                summary=summary,
                duration=duration,
                open_only=open_only,
            )
        )

    return reports


# --- CLI ---


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP port scanner with service detection and fingerprinting."
    )
    parser.add_argument("target", help="IP address or domain name")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "--ports",
        help="Port range list (e.g., 1-1024,8080)",
    )
    port_group.add_argument(
        "--top",
        choices=sorted(TOP_PORT_PRESETS.keys()),
        help="Use curated common ports list (20, 50, or 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Connection timeout in seconds",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=DEFAULT_READ_TIMEOUT,
        help="Read timeout for banners and probes",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=200,
        help="Number of concurrent workers",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry attempts for timeouts",
    )
    parser.add_argument(
        "--backoff",
        type=float,
        default=0.2,
        help="Delay between retries in seconds",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="Limit new connections per second (0 = unlimited)",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Show only open ports",
    )
    parser.add_argument(
        "--fingerprint",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable service fingerprinting",
    )
    parser.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable TLS probing for HTTPS ports",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        help="Write output to a file instead of stdout",
    )
    parser.set_defaults(ports="1-1024")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        raise ValueError("Timeout must be positive.")
    if args.read_timeout <= 0:
        raise ValueError("Read timeout must be positive.")
    if args.workers <= 0:
        raise ValueError("Workers must be positive.")
    if args.retries <= 0:
        raise ValueError("Retries must be positive.")
    if args.backoff < 0:
        raise ValueError("Backoff must be zero or positive.")
    if args.rate < 0:
        raise ValueError("Rate must be zero or positive.")


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        ports = TOP_PORT_PRESETS[args.top] if args.top else parse_ports(args.ports)
        validate_args(args)
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    try:
        reports = asyncio.run(
            scan_target(
                args.target,
                ports,
                args.timeout,
                args.workers,
                args.retries,
                args.tls,
                args.fingerprint,
                args.read_timeout,
                args.backoff,
                args.rate,
                args.open_only,
            )
        )
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[info] Scan interrupted by user.", file=sys.stderr)
        return 130

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
