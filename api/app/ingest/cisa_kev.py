import requests
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev(source):
    r = requests.get(KEV_URL, timeout=60)
    data = r.json()
    out = []
    for v in data.get("vulnerabilities", []):
        title = f"{v.get('cveID')}: {v.get('vendorProject','')} {v.get('product','')}".strip()
        text = f"{v.get('shortDescription','')}".strip()
        url = v.get("cveURL") or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        publ = v.get("dateAdded")
        try:
            published_at = datetime.fromisoformat(publ.replace("Z","+00:00")) if publ else None
        except Exception:
            published_at = None
        out.append({
            "canonical_url": url,
            "title": title,
            "published_at": published_at,
            "author": "CISA",
            "raw": v,
            "text": text,
            "summary_short": None
        })
    return out
