import sqlite3
import json
import urllib.request
from typing import List, Optional

CVE_CACHE_FILE = "cve_cache.db"

def init_cve_cache():
    try:
        conn = sqlite3.connect(CVE_CACHE_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS cve_data (service text, version text, cves text)''')
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_cve_from_cache(service: str, version: str) -> Optional[List[str]]:
    try:
        conn = sqlite3.connect(CVE_CACHE_FILE)
        c = conn.cursor()
        c.execute('SELECT cves FROM cve_data WHERE service=? AND version=?', (service, version))
        row = c.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None

def save_cve_to_cache(service: str, version: str, cves: List[str]):
    try:
        conn = sqlite3.connect(CVE_CACHE_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO cve_data VALUES (?,?,?)', (service, version, json.dumps(cves)))
        conn.commit()
        conn.close()
    except Exception:
        pass

def lookup_cves_for_service(service: str, version: str) -> List[str]:
    """Basic CVE lookup using Circl API with SQLite Caching."""
    if not service or not version or version == "-" or service == "unknown":
        return []
    
    cached = get_cve_from_cache(service, version)
    if cached is not None:
        return cached

    query = f"{service} {version}".replace(" ", "%20")
    url = f"https://cve.circl.lu/api/search/{query}"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'BetaScan/1.0'})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                cves = [item['id'] for item in data.get('results', [])[:5]]
                save_cve_to_cache(service, version, cves)
                return cves
    except Exception:
        pass
    return []