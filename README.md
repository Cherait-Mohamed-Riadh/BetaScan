<div align="center">
  <h1>BetaScan</h1>
  <p><b>Advanced Asynchronous TCP/UDP Port Scanner & Exploitation Framework</b></p>
  
  [![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  [![Security Level](https://img.shields.io/badge/Auditing-Advanced-red.svg)]()
  
  <i>Developed by <b>Cherait Mohamed Riadh</b></i>
</div>

## Overview

**BetaScan** is a cutting-edge, modular, and asynchronous network exploration and vulnerability auditing framework. By seamlessly combining the raw concurrency of `asyncio` with the low-level packet manipulation power of `Scapy`, BetaScan delivers lightning-fast scanning speeds alongside advanced firewall evasion techniques and dynamic scripting capabilities.

Designed for penetration testers, security researchers, and network administrators, BetaScan offers enterprise-grade stability and extensive fingerprinting functionality inside a highly customizable, lightweight package.

## Core Features

### Advanced Scanning Capabilities
- **Massively Parallel:** Asynchronous networking engine built on `asyncio` designed to scale beyond OS networking limits.
- **Stealth SYN Scan (`-sS`):** Sends raw SYN packets and monitors responses, terminating half-open connections with an immediate `RST` to evade logging.
- **State-Based Evasion:** Implements FIN (`-sF`), Xmas (`-sX`), and Null (`-sN`) scanning options to trick stateless packet filters.
- **UDP Auditing (`-sU`):** Robust UDP port mapping via ICMP unreachable interpretation.

### Deep Fingerprinting & Recognition
- **Smart Target Resolution:** Full support for IP addresses, DNS domains, and CIDR network blocks (e.g., `192.168.1.0/24`).
- **OS Guessing (`-O`):** Advanced OS fingerprinting utilizing returned Time-To-Live (TTL) and TCP Window Size metrics.
- **Intelligent Banner Grabbing:** Automated protocol validation, extracting TLS ciphers, HTTP server versions, and certificate metadata natively.

### Vulnerabilities & Exploitation
- **Dynamic YAML Engine (`--script`):** Bring your own probes! Execute targeted, human-readable YAML scripts instantly from the local `scripts/` directory.
- **On-Demand CVE Lookup (`--cve`):** Auto-queries security APIs for detected versions and maps them to known vulnerabilities.
- **Built-in SQLite Cache:** Stores CVE definitions in a highly efficient local SQLite database, boosting speeds by 400% on rescans while avoiding API bans.

### Defense Evasion Mechanism
- **Automated Kernel Hooks:** BetaScan automatically injects `iptables` rules locally to silence your OS Kernel from sending auto-RST responses during Scapy scans, reverting cleanly upon exit.
- **Decoy Scanning (`-D`):** Mask your true IP by spoofing and interleaving scanning traffic with decoy addresses.
- **Packet Fragmentation (`-f`):** Slices outgoing packets to confuse Deep Packet Inspection (DPI) and Intrusion Detection Systems (IDS).

### Enterprise & Red Team Features (New!)

* **Distributed Mass Scanning (Master-Worker):** Scale your scanning capabilities by deploying a centralized controller (`--master`) that dynamically assigns targets to multiple decentralized probing units (`--worker`).
* **Two-Phase Host Discovery (`--phase1`):** Optimizes network bandwidth by pinging/probing active hosts first before initiating intensive scripts or full port sweeps.
* **Host & Port Randomization (`--randomize`):** Scrambles target sequences globally across subnet layers to obfuscate traffic signatures against modern Intrusion Detection Systems (IDS).
* **Asynchronous Proxy Swarms (`--proxy`):** Full, non-blocking SOCKS5 proxy integration via `aiohttp-socks` to mask source signatures.
* **Scan Session Resumption (`--resume`):** Fault-tolerant state saving powered by SQLite3. Instantly resume interrupted scans without losing telemetry.
* **Executive Reporting Engine:** Export data as industrial-grade HTML interactive dashboards (embedded with Chart.js analytics via Jinja2 templates) or stream real-time results directly via Line-Delimited JSON (`ndjson`).

## Project Structure

```text
betascan/
├── betascan.py           # CLI Engine & Main Entry Point
├── config.py             # Global settings, presets, and constants
├── database.py           # Local SQLite Cache Model for CVEs
├── core/
│   ├── scanner.py        # Async Engine, Packet Handler, OS detection
│   └── script_engine.py  # YAML Scripting Interpreter
├── scripts/              
│   ├── http_git_check.yaml    # Example: Exposes open /.git/ folders
│   └── ssh_version_check.yaml # Example: Custom SSH protocol banner probe
├── README.md             # Documentation
└── requirements.txt      # Project Dependencies
```

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Cherait-Mohamed-Riadh/BetaScan.git
cd BetaScan

# 2. Install dependencies
pip install -r requirements.txt

# Note: Advanced Scapy evasion and root-level scans require sudo/root privileges.
```

## Usage Examples

**1. Basic Port Scan** (Fast scanning using pure asyncio)
```bash
python betascan.py 192.168.1.1 --top 100
```

**2. Stealth Auditing with OS Fingerprinting & CVE Lookups**
Run a full stealth SYN scan with OS guessing, CVE lookups, timing template 4, and automated firewall rules handling:
```bash
sudo python betascan.py 10.10.10.0/24 -sS -O --cve -T 4 
```

**3. Evading Defenses via Fragmentation and Decoys**
Combine MAC spoofing, decoys, packet fragmentation, and Xmas-tree flags to slip past restrictive stateful firewalls:
```bash
sudo python betascan.py scanme.org -sX -f -D 8.8.8.8,1.1.1.1 --spoof-mac 00:11:22:33:44:55
```

**4. Execute Dynamic Custom Scripts**
Run a specific application-layer vulnerability check using YAML scripts against a dedicated target:
```bash
python betascan.py 172.16.5.15 --script http_git_check --format json -o results.json
```

### Advanced Enterprise Production Usage

#### 1. Spinning up a Distributed Scanning Cluster
On your core command server (Master Node):
```bash
sudo python3 betascan.py --master --output cluster_db.sqlite
```

On your remote perimeter deployment VPS (Worker Nodes):
```bash
sudo python3 betascan.py --worker --connect http://<MASTER_IP>:9999
```

#### 2. Stealth Network Sweeping with Resumption and Proxy Masking
Scan a wide subnet routing through a SOCKS5 proxy, randomizing patterns, and caching states to ensure you can resume if the proxy drops:
```bash
sudo python3 betascan.py 10.0.0.0/16 --randomize --proxy socks5://127.0.0.1:9050 --phase1 --resume redteam_ops_session
```

#### 3. Generating C-Level Executive Dashboard Reports
Execute a thorough vulnerability scan and output an interactive, graphical HTML report alongside raw NDJSON data:
```bash
sudo python3 betascan.py company.com --top 100 --cve --format html --output /var/www/html/report.html
```

## Disclaimer
**This tool is intended for legal, authorized security auditing and educational purposes only.** 
The author, **Cherait Mohamed Riadh**, is not responsible for any misuse, damage, or illegal activities caused by utilizing this software. Always ensure you have explicit written permission from the network owner before performing any security scans.

---
<div align="center">
  Crafted with for the Cybersecurity Community by <b>Cherait Mohamed Riadh</b>.
</div>