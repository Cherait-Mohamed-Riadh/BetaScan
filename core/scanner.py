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
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from config import (
    PORT_SPECS, PROBE_COMMANDS, HTTP_PORTS, SERVICE_HINTS, 
    MAX_BANNER_BYTES, MAX_VERSION_LEN
)
from database import lookup_cves_for_service
from core.script_engine import run_dynamic_scripts, run_script_engine

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass(frozen=False)
class ScanResult:
    port: int
    protocol: str
    status: str
    service: str
    version: str
    cves: List[str] = field(default_factory=list)

@dataclass(frozen=False)
class ScanReport:
    target: str
    ip: str
    results: List[ScanResult]
    summary: dict
    duration: float
    open_only: bool
    os_match: str = "Unknown"

@dataclass(frozen=True)
class TargetAddress:
    ip: str
    family: int

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

def parse_ports(spec: str) -> List[int]:
    """Parse a port specification like "1-1024,8080" into a sorted list."""
    if not spec:
        raise ValueError("Port specification cannot be empty.")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part: continue
        try:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str), int(end_str)
            else:
                start = end = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid port token: {part}") from exc
        if start > end: start, end = end, start
        for port in range(start, end + 1):
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.add(port)
    if not ports: raise ValueError("No valid ports found.")
    return sorted(ports)

def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253: return False
    if hostname.endswith("."): hostname = hostname[:-1]
    for label in hostname.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    return True

def resolve_target(target: str) -> List[TargetAddress]:
    results: List[TargetAddress] = []
    
    # 1. CIDR support
    if '/' in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                family = socket.AF_INET6 if net.version == 6 else socket.AF_INET
                results.append(TargetAddress(ip=str(ip), family=family))
            if not results:
                family = socket.AF_INET6 if net.version == 6 else socket.AF_INET
                results = [TargetAddress(ip=str(ip), family=family) for ip in net]
            return results
        except ValueError:
            pass

    # 2. IP explicit
    try:
        ipaddress.ip_address(target)
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        return [TargetAddress(ip=target, family=family)]
    except ValueError:
        pass

    # 3. Domain Name
    if not is_valid_hostname(target):
        raise ValueError(f"Invalid domain name or CIDR: {target}")

    seen = set()
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            if ip not in seen:
                results.append(TargetAddress(ip=ip, family=family))
                seen.add(ip)
        return results
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target: {target}") from exc

def guess_service(port: int, banner: str) -> str:
    if port in SERVICE_HINTS: return SERVICE_HINTS[port]
    if not banner: return ""
    lower = banner.lower()
    if lower.startswith("ssh-"): return "ssh"
    if lower.startswith("http/"): return "http"
    if "smtp" in lower or "esmtp" in lower: return "smtp"
    if lower.startswith("220") and "ftp" in lower: return "ftp"
    if lower.startswith("* ok"): return "imap"
    if lower.startswith("+ok") and "pop" in lower: return "pop3"
    if lower.startswith("+pong"): return "redis"
    if "imap" in lower: return "imap"
    if "pop3" in lower: return "pop3"
    if "mysql" in lower: return "mysql"
    if "postgres" in lower: return "postgresql"
    if "redis" in lower: return "redis"
    try: return socket.getservbyport(port, "tcp")
    except OSError: return "unknown"

def trim_version(text: str) -> str:
    cleaned = " ".join(text.split())
    return cleaned if len(cleaned) <= MAX_VERSION_LEN else cleaned[: MAX_VERSION_LEN - 3] + "..."

def build_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def extract_common_name(name_entries: Sequence[Tuple[Tuple[str, str], ...]]) -> str:
    for entry in name_entries:
        for key, value in entry:
            if key.lower() == "commonname": return value
    return ""

def format_cert_info(cert: dict) -> str:
    if not cert: return ""
    cn = extract_common_name(cert.get("subject", ()))
    issuer_cn = extract_common_name(cert.get("issuer", ()))
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    san_text = f"SAN: {', '.join(sans[:3])} (+{len(sans)-3} more)" if len(sans) > 3 else f"SAN: {', '.join(sans)}" if sans else ""
    return "; ".join([p for p in [f"CN={cn}" if cn else "", f"Issuer={issuer_cn}" if issuer_cn else "", san_text] if p])

def format_tls_info(ssl_obj: Optional[ssl.SSLObject]) -> str:
    if not ssl_obj: return ""
    version = ssl_obj.version() or ""
    cipher_info = ssl_obj.cipher()
    cipher = cipher_info[0] if cipher_info else ""
    cert_info = format_cert_info(ssl_obj.getpeercert())
    base = " ".join(p for p in ["TLS", version, cipher] if p)
    return f"{base}; {cert_info}" if cert_info else base

async def read_with_timeout(reader: asyncio.StreamReader, timeout: float, max_bytes: int) -> str:
    try: return (await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)).decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError): return ""

async def write_with_timeout(writer: asyncio.StreamWriter, data: bytes, timeout: float) -> bool:
    try:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        return True
    except (asyncio.TimeoutError, OSError): return False

async def command_probe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, command: str, host_hint: str, timeout: float, read_banner: bool) -> str:
    banner = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES) if read_banner else ""
    command_line = command.format(host=host_hint if is_valid_hostname(host_hint) else "scan.local")
    if not await write_with_timeout(writer, command_line.encode("ascii", errors="ignore"), timeout): return banner
    resp = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
    return "; ".join([p for p in [banner, resp] if p])

async def http_probe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, timeout: float) -> str:
    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BetaScan/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    if not await write_with_timeout(writer, request.encode("ascii", errors="ignore"), timeout): return ""
    response = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
    if not response: return ""
    headers = response.split("\r\n")
    server, powered = "", ""
    for header in headers[1:]:
        if header.lower().startswith("server:"): server = header.split(":", 1)[1].strip()
        if header.lower().startswith("x-powered-by:"): powered = header.split(":", 1)[1].strip()
    return "; ".join(p for p in [headers[0].strip() if headers else "", f"Server: {server}" if server else "", f"X-Powered-By: {powered}" if powered else ""] if p)

async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    if hasattr(writer, "wait_closed"):
        try: await writer.wait_closed()
        except OSError: pass

def classify_os_error(exc: OSError) -> str:
    refused = {errno.ECONNREFUSED, 10061}
    timeouts = {errno.ETIMEDOUT, 10060, errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}
    err = exc.errno
    win = getattr(exc, "winerror", None)
    if err in refused or win in refused: return "closed"
    return "filtered"

_global_proxy = None
def set_global_proxy(proxy_url: str):
    global _global_proxy
    _global_proxy = proxy_url

async def open_tcp_connection(address: TargetAddress, port: int, timeout: float) -> Tuple[str, Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
    try:
        if _global_proxy:
            from aiohttp_socks import open_connection as socks_open_connection
            reader, writer = await asyncio.wait_for(socks_open_connection(socks_url=_global_proxy, host=address.ip, port=port), timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host=address.ip, port=port, family=address.family), timeout=timeout)
        return "open", reader, writer
    except asyncio.TimeoutError: return "filtered", None, None
    except ConnectionRefusedError: return "closed", None, None
    except OSError as exc: return classify_os_error(exc), None, None
    except Exception as exc: return "filtered", None, None

async def tls_app_probe(address: TargetAddress, port: int, host_hint: str, timeout: float, app: str) -> Tuple[str, str]:
    try:
        if _global_proxy:
            from aiohttp_socks import open_connection as socks_open_connection
            reader, writer = await asyncio.wait_for(socks_open_connection(socks_url=_global_proxy, host=address.ip, port=port, ssl=build_tls_context(), server_hostname=host_hint), timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host=address.ip, port=port, family=address.family, ssl=build_tls_context(), server_hostname=host_hint), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError, Exception): return "", ""
    tls_info = format_tls_info(writer.get_extra_info("ssl_object"))
    try:
        if app == "http": banner = await http_probe(reader, writer, host_hint, timeout)
        elif app in PROBE_COMMANDS: banner = await command_probe(reader, writer, PROBE_COMMANDS[app], host_hint, timeout, True)
        else: banner = await read_with_timeout(reader, timeout, MAX_BANNER_BYTES)
    finally: await close_writer(writer)
    return banner, tls_info

async def fingerprint_open_port(address: TargetAddress, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host_hint: str, timeout: float, use_tls: bool, read_timeout: float) -> Tuple[str, str]:
    read_timeout = min(timeout, read_timeout)
    banner, tls_info = "", ""
    spec = PORT_SPECS.get(port)
    if spec and spec.banner: banner = await read_with_timeout(reader, read_timeout, MAX_BANNER_BYTES)
    if spec and spec.probe:
        probe_info = await command_probe(reader, writer, PROBE_COMMANDS[spec.probe], host_hint, read_timeout, spec.banner and not banner)
        banner = "; ".join([p for p in [banner, probe_info] if p])
    if not banner and port in HTTP_PORTS: banner = await http_probe(reader, writer, host_hint, read_timeout)
    if use_tls and spec and spec.tls_app:
        tls_banner, tls_info = await tls_app_probe(address, port, host_hint, read_timeout, spec.tls_app)
        banner = "; ".join([p for p in [banner, tls_banner] if p])
    service = guess_service(port, banner)
    version = "; ".join([p for p in [tls_info, banner] if p]) or "-"
    return service, trim_version(version)

def scapy_scan_port_sync(ip: str, port: int, scan_type: str, timeout: float, decoy: str = None, spoof_mac: str = None, fragment: bool = False) -> Tuple[str, str]:
    if not SCAPY_AVAILABLE: return "filtered", "tcp"
    real_ip = scapy.conf.iface.ip
    decoy_ips = [d.strip() for d in decoy.split(',')] if decoy else []
    eth_layer = scapy.Ether(src=spoof_mac) if spoof_mac else None

    def build_pkt(src_ip):
        ip_layer = scapy.IP(dst=ip, src=src_ip)
        if fragment: ip_layer.flags = "MF"
        if scan_type == "SYN": layer = scapy.TCP(dport=port, flags="S")
        elif scan_type == "UDP": layer = scapy.UDP(dport=port)
        elif scan_type in ["FIN", "XMAS", "NULL"]: layer = scapy.TCP(dport=port, flags="F" if scan_type == "FIN" else ("FPU" if scan_type == "XMAS" else ""))
        else: layer = scapy.TCP(dport=port, flags="S")
        pkt = ip_layer / layer
        if eth_layer: pkt = eth_layer / pkt
        return pkt

    for d_ip in decoy_ips:
        if d_ip != 'ME' and d_ip != real_ip: scapy.send(build_pkt(d_ip), verbose=0)
        
    real_pkt = build_pkt(real_ip)
    
    if scan_type == "SYN":
        resp = scapy.sr1(real_pkt, timeout=timeout, verbose=0)
        if resp is None: return "filtered", "tcp"
        elif resp.haslayer(scapy.TCP):
            if resp.getlayer(scapy.TCP).flags == 0x12:
                rst_pkt = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="R")
                if eth_layer: rst_pkt = eth_layer / rst_pkt
                scapy.send(rst_pkt, verbose=0)
                return "open", "tcp"
            elif resp.getlayer(scapy.TCP).flags == 0x14: return "closed", "tcp"
    
    elif scan_type == "UDP":
        resp = scapy.sr1(real_pkt, timeout=timeout, verbose=0)
        if resp is None: return "open|filtered", "udp"
        elif resp.haslayer(scapy.UDP): return "open", "udp"
        elif resp.haslayer(scapy.ICMP):
            if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 9, 10, 13]: return "filtered", "udp"
            if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) == 3: return "closed", "udp"
            
    elif scan_type in ["FIN", "XMAS", "NULL"]:
        resp = scapy.sr1(real_pkt, timeout=timeout, verbose=0)
        if resp is None: return "open|filtered", "tcp"
        elif resp.haslayer(scapy.TCP):
            if resp.getlayer(scapy.TCP).flags == 0x14: return "closed", "tcp"
        elif resp.haslayer(scapy.ICMP):
            if int(resp.getlayer(scapy.ICMP).type) == 3 and int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]: return "filtered", "tcp"

    return "filtered", "tcp"

def scapy_os_fingerprint_sync(ip: str, timeout: float) -> str:
    if not SCAPY_AVAILABLE: return "Unknown"
    resp = scapy.sr1(scapy.IP(dst=ip) / scapy.ICMP(), timeout=timeout, verbose=0)
    if resp and resp.haslayer(scapy.IP):
        ttl = resp.getlayer(scapy.IP).ttl
        if ttl <= 64: return "Linux/Unix (TTL ~64)"
        elif ttl <= 128: return "Windows (TTL ~128)"
        elif ttl <= 255: return "Cisco/Solaris (TTL ~255)"
    return "Unknown"

async def scan_port(
    address: TargetAddress, port: int, timeout: float, retries: int, host_hint: str, use_tls: bool, 
    fingerprint: bool, read_timeout: float, backoff: float, limiter: Optional[RateLimiter], 
    scan_type: str = "TCP", decoy: str = None, spoof_mac: str = None, fragment: bool = False, 
    lookup_cve: bool = False, script_name: str = None, dynamic_scripts: List[dict] = None
) -> ScanResult:
    statuses = []
    for attempt in range(max(1, retries)):
        if limiter: await limiter.wait()
        status, protocol, reader, writer = "filtered", "tcp", None, None
        
        if scan_type == "TCP":
            status, reader, writer = await open_tcp_connection(address, port, timeout)
        else:
            status, protocol = await asyncio.to_thread(scapy_scan_port_sync, address.ip, port, scan_type, timeout, decoy, spoof_mac, fragment)

        if status in ["open", "open|filtered"]:
            service, version, cves = "-", "-", []
            if fingerprint:
                if reader and writer: service, version = await fingerprint_open_port(address, port, reader, writer, host_hint, timeout, use_tls, read_timeout)
                elif protocol == "tcp":
                    try:
                        _, t_reader, t_writer = await open_tcp_connection(address, port, timeout)
                        if t_reader and t_writer:
                            service, version = await fingerprint_open_port(address, port, t_reader, t_writer, host_hint, timeout, use_tls, read_timeout)
                            await close_writer(t_writer)
                    except Exception: service = guess_service(port, "")
                else: service = guess_service(port, "")
            else: service = guess_service(port, "")
            
            if reader and writer: await close_writer(writer)
            
            if lookup_cve and version != "-": cves = await asyncio.to_thread(lookup_cves_for_service, service, version)
            if script_name:
                s_res = run_script_engine(script_name, port, service)
                if s_res: version = f"{version} [{s_res}]"
            if dynamic_scripts:
                d_res = await run_dynamic_scripts(address, port, host_hint, timeout, dynamic_scripts)
                if d_res: version = f"{version} [{' | '.join(d_res)}]"
                
            return ScanResult(port, protocol, status, service or "unknown", version or "-", cves or [])
            
        statuses.append(status)
        if status == "filtered" and backoff > 0 and attempt < retries - 1:
            await asyncio.sleep(backoff * (attempt + 1)) # Smart Retries feature!

    return ScanResult(port, "tcp", "closed" if "closed" in statuses else "filtered", "-", "-", [])


async def scan_target(
    target: str, ports: Iterable[int], timeout: float, workers: int, retries: int, use_tls: bool, 
    fingerprint: bool, read_timeout: float, backoff: float, rate: float, open_only: bool, 
    reports_list: List[ScanReport], scan_type: str = "TCP", do_os: bool = False, do_cve: bool = False, 
    script_name: str = None, decoy: str = None, spoof_mac: str = None, fragment: bool = False, dynamic_scripts: List[dict] = None,
    randomize: bool = False, phase1: bool = False, resume_session: str = None, proxy: str = None,
    is_master: bool = False, is_worker: bool = False, output_format: str = None, output_file: str = None
) -> None:
    if proxy:
        set_global_proxy(proxy)
    
    addresses = resolve_target(target)
    if randomize:
        import random
        random.shuffle(addresses)
    
    for address in addresses:
        if phase1:
            # Phase 1: simple ICMP/TCP ping to check if alive
            if scan_type != "UDP": # simple check
                try:
                    p1_status, _, _ = await open_tcp_connection(address, 80, min(timeout, 1.0))
                    if p1_status not in ["open", "closed", "open|filtered"]:
                        continue # Skip this host
                except Exception:
                    continue

        if resume_session:
            import sqlite3
            try:
                conn = sqlite3.connect("session_cache.db")
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS session_state (session_name text, ip text)''')
                c.execute('SELECT ip FROM session_state WHERE session_name=? AND ip=?', (resume_session, address.ip))
                if c.fetchone():
                    conn.close()
                    continue # Already scanned
                conn.close()
            except Exception:
                pass

        results = []
        semaphore = asyncio.Semaphore(workers)
        limiter = RateLimiter(rate) if rate > 0 else None
        
        # Graceful handling logic: we append report structure immediately to reports_list
        report = ScanReport(target, address.ip, results, {"total": 0}, 0.0, open_only, "Unknown")
        reports_list.append(report)

        if do_os: report.os_match = await asyncio.to_thread(scapy_os_fingerprint_sync, address.ip, timeout)

        async def bounded_scan(port: int):
            async with semaphore:
                res = await scan_port(address, port, timeout, retries, target, use_tls, fingerprint, read_timeout, backoff, limiter, scan_type, decoy, spoof_mac, fragment, do_cve, script_name, dynamic_scripts)
                if output_format == "ndjson":
                    import json
                    record = {"ip": address.ip, "port": res.port, "status": res.status, "service": res.service, "version": res.version, "cves": res.cves}
                    out_line = json.dumps(record) + "\n"
                    if output_file:
                        with open(output_file, "a", encoding="utf-8") as f:
                            f.write(out_line)
                    else:
                        print(out_line.strip())
                return res

        port_list = list(ports)
        if randomize:
            import random
            random.shuffle(port_list)
            
        tasks = [asyncio.create_task(bounded_scan(p)) for p in port_list]
        start_time = time.perf_counter()
        try:
            for task in asyncio.as_completed(tasks):
                results.append(await task)
        except asyncio.CancelledError:
            pass # Keep results received so far (Graceful partial shutdown)
            
        results.sort(key=lambda r: r.port)
        if open_only: report.results = [r for r in results if r.status in ("open", "open|filtered")]
        report.duration = time.perf_counter() - start_time
        report.summary = {"open": sum(1 for r in results if r.status in ("open", "open|filtered")), "closed": sum(1 for r in results if r.status == "closed"), "filtered": sum(1 for r in results if r.status == "filtered"), "total": len(results)}

        if resume_session:
            try:
                conn = sqlite3.connect("session_cache.db")
                c = conn.cursor()
                c.execute('INSERT INTO session_state (session_name, ip) VALUES (?, ?)', (resume_session, address.ip))
                conn.commit()
                conn.close()
            except Exception:
                pass


# Formatters
def render_table(rows: Sequence[ScanResult]) -> str:
    headers = ["Port", "Proto", "Status", "Service", "Version", "Vulnerabilities"]
    data = [[str(r.port), r.protocol, r.status, r.service, r.version, ", ".join(r.cves) if r.cves else "-"] for r in rows]
    widths = [max(len(h), max((len(row[i]) for row in data), default=0)) for i, h in enumerate(headers)]
    def fmt(cells): return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    return "\n".join([sep, fmt(headers), sep] + [fmt(row) for row in data] + [sep])

def format_summary(report: ScanReport) -> str:
    s = report.summary
    parts = [f"Scanned: {s.get('total',0)}", f"Open: {s.get('open',0)}", f"Closed: {s.get('closed',0)}", f"Filtered: {s.get('filtered',0)}", f"Duration: {report.duration:.2f}s"]
    if report.os_match != "Unknown": parts.append(f"OS: {report.os_match}")
    if report.open_only: parts.append(f"Displayed: {len(report.results)}")
    return "Summary: " + ", ".join(parts)

def render_table_output(reports: Sequence[ScanReport]) -> str:
    return "\n".join(f"\nTarget: {r.target} ({r.ip})\n" + (f"OS Detection: {r.os_match}\n" if r.os_match != "Unknown" else "") + render_table(r.results) + "\n" + format_summary(r) for r in reports).strip()

def report_to_dict(r: ScanReport) -> dict:
    return {"target": r.target, "ip": r.ip, "os_match": r.os_match, "duration_seconds": round(r.duration, 3), "summary": r.summary, "open_only": r.open_only, "displayed_count": len(r.results), "results": [{"port": row.port, "protocol": row.protocol, "status": row.status, "service": row.service, "version": row.version, "cves": row.cves or []} for row in r.results]}

def render_json_output(reports: Sequence[ScanReport]) -> str:
    return json.dumps([report_to_dict(r) for r in reports], indent=2, ensure_ascii=True)

def render_ndjson_output(reports: Sequence[ScanReport]) -> str:
    return "\n".join(json.dumps(report_to_dict(r)) for r in reports)

def render_html_output(reports: Sequence[ScanReport]) -> str:
    try:
        from jinja2 import Template
    except ImportError:
        return "<html><body><h1>Error: jinja2 required for HTML reports. run pip install jinja2</h1></body></html>"
    template_str = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>BetaScan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f9; }
            h1 { color: #333; }
            .report-card { background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #0056b3; color: white; }
            tr:hover { background-color: #f1f1f1; }
            .high { color: red; font-weight: bold; }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <h1>BetaScan Target Reports</h1>
        {% for report in reports %}
        <div class="report-card">
            <h2>Target: {{ report.target }} ({{ report.ip }})</h2>
            <p><strong>OS:</strong> {{ report.os_match }} | <strong>Duration:</strong> {{ report.duration|round(2) }}s</p>
            <div style="width: 300px; height: 300px; margin: 0 auto;">
                <canvas id="chart-{{ loop.index }}"></canvas>
            </div>
            <table>
                <tr><th>Port</th><th>Proto</th><th>Status</th><th>Service</th><th>Version</th><th>CVEs</th></tr>
                {% for row in report.results %}
                <tr>
                    <td>{{ row.port }}</td><td>{{ row.protocol }}</td><td>{{ row.status }}</td>
                    <td>{{ row.service }}</td><td>{{ row.version }}</td>
                    <td class="{% if row.cves %}high{% endif %}">{{ row.cves|join(', ') if row.cves else '-' }}</td>
                </tr>
                {% endfor %}
            </table>
            <script>
            var ctx = document.getElementById('chart-{{ loop.index }}').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Open', 'Closed', 'Filtered'],
                    datasets: [{
                        data: [{{ report.summary.get('open',0) }}, {{ report.summary.get('closed',0) }}, {{ report.summary.get('filtered',0) }}],
                        backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                    }]
                }
            });
            </script>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    return Template(template_str).render(reports=reports)

def render_csv_output(reports: Sequence[ScanReport]) -> str:
    b = io.StringIO()
    w = csv.writer(b)
    w.writerow(["target", "ip", "port", "protocol", "status", "service", "version"])
    for r in reports:
        for row in r.results: w.writerow([r.target, r.ip, row.port, row.protocol, row.status, row.service, row.version])
    return b.getvalue().strip("\n")

def write_output(content: str, output_path: Optional[str]) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as h: h.write(content)
    else: print(content)

def run_master_node(target: str, ports: List[int]):
    print(f"[Master] Initializing master node for {target} on ports {ports[:5]}...")
    import http.server
    import socketserver
    import sqlite3
    
    addresses = resolve_target(target)
    ips = [a.ip for a in addresses]
    
    try:
        conn = sqlite3.connect("master_queue.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tasks (ip text primary key, status text)''')
        c.execute('''CREATE TABLE IF NOT EXISTS results (ip text, data text)''')
        for ip in ips:
            c.execute('INSERT OR IGNORE INTO tasks (ip, status) VALUES (?, ?)', (ip, 'pending'))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Master] Error setting up DB: {e}")
        return

    class MasterHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/get_task':
                try:
                    conn = sqlite3.connect("master_queue.db")
                    c = conn.cursor()
                    c.execute('SELECT ip FROM tasks WHERE status="pending" LIMIT 1')
                    row = c.fetchone()
                    if row:
                        ip = row[0]
                        c.execute('UPDATE tasks SET status="assigned" WHERE ip=?', (ip,))
                        conn.commit()
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(ip.encode('utf-8'))
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b'NONE')
                    conn.close()
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()
                
        def do_POST(self):
            if self.path == '/submit_result':
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    data = self.rfile.read(length)
                    result_json = json.loads(data.decode('utf-8'))
                    ip = result_json.get('ip')
                    conn = sqlite3.connect("master_queue.db")
                    c = conn.cursor()
                    c.execute('UPDATE tasks SET status="completed" WHERE ip=?', (ip,))
                    c.execute('INSERT INTO results (ip, data) VALUES (?, ?)', (ip, data.decode('utf-8')))
                    conn.commit()
                    conn.close()
                    self.send_response(200)
                    self.end_headers()
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

    PORT = 9999
    with socketserver.TCPServer(("", PORT), MasterHandler) as httpd:
        print(f"[Master] Serving on port {PORT}. Waiting for workers...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[Master] Shutting down.")

async def run_worker_node(master_url: str, ports: List[int], args):
    print(f"[Worker] Connecting to master at {master_url}...")
    import urllib.request
    import urllib.error
    
    while True:
        try:
            req = urllib.request.Request(f"http://{master_url}:9999/get_task")
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    ip = response.read().decode('utf-8')
                    if ip == "NONE":
                        print("[Worker] No more tasks. Exiting.")
                        break
                    
                    print(f"[Worker] Received task: {ip}. Scanning...")
                    reports = []
                    await scan_target(
                        ip, ports, args.timeout, args.workers, args.retries, args.tls, args.fingerprint, 
                        args.read_timeout, args.backoff, args.rate, args.open_only,
                        reports_list=reports, proxy=args.proxy
                    )
                    
                    if reports:
                        res_data = report_to_dict(reports[0])
                        post_req = urllib.request.Request(f"http://{master_url}:9999/submit_result", data=json.dumps(res_data).encode('utf-8'), method="POST")
                        post_req.add_header('Content-Type', 'application/json')
                        urllib.request.urlopen(post_req, timeout=5)
                        print(f"[Worker] Submitted results for {ip}.")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print("[Worker] No more tasks. Exiting.")
                break
        except Exception as e:
            print(f"[Worker] Error: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)