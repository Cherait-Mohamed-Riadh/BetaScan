from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PortSpec:
    service: str
    banner: bool = False
    probe: Optional[str] = None
    tls_app: Optional[str] = None

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