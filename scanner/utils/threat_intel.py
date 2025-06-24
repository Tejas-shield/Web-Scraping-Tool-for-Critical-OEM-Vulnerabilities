# scanner/utils/threat_intel.py

from virustotal_python import Virustotal, VirustotalError
import os

def enrich_via_virustotal(cve_id):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("⚠️ VT_API_KEY not set")
        return {}

    vt = Virustotal(API_KEY=api_key)
    
    try:
        # Attempt to fetch info using VirusTotal’s vulnerability lookup
        resp = vt.request(f"vulnerabilities/{cve_id}")
        data = resp.get("data", {})

        return {
            "vt_score": data.get("attributes", {}).get("severity", "N/A"),
            "exploits": data.get("attributes", {}).get("exploits", [])
        }

    except VirustotalError as e:
        print(f"🔍 VirusTotal Error for {cve_id}: {e}")
        return {
            "vt_score": "Not found",
            "exploits": []
        }
