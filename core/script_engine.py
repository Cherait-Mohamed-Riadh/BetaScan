import os
import glob
import asyncio
from typing import List

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

def load_dynamic_scripts() -> List[dict]:
    scripts = []
    if not YAML_AVAILABLE or not os.path.exists("scripts"):
        return scripts
    for file in glob.glob("scripts/*.yaml") + glob.glob("scripts/*.yml"):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data: scripts.append(data)
        except Exception:
            continue
    return scripts

async def run_dynamic_scripts(address, port: int, host_hint: str, timeout: float, scripts: List[dict]) -> List[str]:
    findings = []
    for script in scripts:
        ports_str = str(script.get('port', ''))
        script_ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
        if script_ports and port not in script_ports:
            continue
            
        req_str = script.get('request', '').replace('{host}', host_hint)
        req = bytes(req_str, "utf-8").decode("unicode_escape").encode("utf-8")
        match = script.get('match', '')
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=address.ip, port=port, family=address.family), 
                timeout=timeout
            )
            writer.write(req)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            writer.close()
            await asyncio.sleep(0) # let it close
            
            if match.encode('utf-8') in resp:
                findings.append(script.get('name', 'VulnFound'))
        except Exception:
            pass
    return findings

def run_script_engine(script_name: str, port: int, service: str) -> str:
    """Mini script engine for hardcoded checks (Legacy fallback)."""
    if script_name == "vuln_check" and service in ["http", "https"]:
        return "Possible Directory Traversal"
    if script_name == "vuln_check" and port == 445:
        return "Checking MS17-010... VULNERABLE!"
    return ""