from datetime import datetime, timedelta
import requests

from .models import Vulnerability

def scrape_nvd_vulnerabilities():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)

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

        if title and not Vulnerability.objects.filter(title=title).exists():
            Vulnerability.objects.create(
                title=title,
                source=source,
                link=link
            )
            print(f"Saved: {title}")
