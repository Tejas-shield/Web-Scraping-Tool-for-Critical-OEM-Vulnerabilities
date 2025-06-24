from datetime import datetime, timedelta
import requests
from scanner.utils.email_alerts import send_critical_cve_alert
from scanner.utils.threat_intel import enrich_via_virustotal
from .models import Vulnerability

def enrich_with_threat_intel(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "summary": data.get("summary"),
                "cvss": data.get("cvss"),
                "references": data.get("references", []),
                "vulnerable_product": data.get("vulnerable_product", [])
            }
    except Exception as e:
        print(f"Threat enrichment failed: {e}")
    return {}

def scrape_nvd_vulnerabilities():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 10,
        "startIndex": 0,
        "pubStartDate": start_date.isoformat() + "Z",
        "pubEndDate": end_date.isoformat() + "Z"
    }

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print("Error fetching:", e)
        return

    data = response.json()
    cves = data.get("vulnerabilities", [])

    for item in cves:
        cve_data = item.get("cve", {})
        title = cve_data.get("id")
        source = cve_data.get("sourceIdentifier", "NVD")
        link = f"https://nvd.nist.gov/vuln/detail/{title}"

        # Extract CVSS score/severity
        metrics = cve_data.get("metrics", {})
        cvss = None

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss = {
                "score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity")
            }
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss = {
                "score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity")
            }

        score = cvss["score"] if cvss else None
        severity = cvss["severity"] if cvss else None

        exists = Vulnerability.objects.filter(title=title).exists()

        if not exists:
            Vulnerability.objects.create(
                title=title,
                source=source,
                link=link,
                score=score,
                severity=severity
            )
            print(f"✅ Saved new vulnerability: {title}")

        # 💥 Enriched email alerts for CRITICAL vulnerabilities
        if severity == "CRITICAL":
            try:
                vt = enrich_via_virustotal(title) or {}
                vt_score = vt.get("vt_score", "N/A")
                exploits = vt.get("exploits", [])

                # Fallback summary/affected info
                summary = f"VirusTotal risk score: {vt_score}"
                affected = "Unknown products"

                send_critical_cve_alert(
                    title, source, link, score, summary, affected,
                    vt_score=vt_score, exploits=exploits
                )
                print(f"📧 Enriched alert sent for {title} (VT score: {vt_score})")

            except Exception as e:
                print(f"⚠️ VirusTotal enrichment or alert failed for {title}: {e}")
