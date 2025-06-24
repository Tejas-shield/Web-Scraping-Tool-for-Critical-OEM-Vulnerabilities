from datetime import datetime, timedelta
import requests
from scanner.utils.email_alerts import send_critical_cve_alert

from .models import Vulnerability

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

        if title and not Vulnerability.objects.filter(title=title).exists():
            Vulnerability.objects.create(
                title=title,
                source=source,
                link=link,
                score=score,
                severity=severity
            )
            print(f"Saved: {title} | Severity: {severity} | Score: {score}")
            
            if severity == "CRITICAL":
                send_critical_cve_alert(title, source, link, score)
                
