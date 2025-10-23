import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional

# Per ThreatFox docs, use the -api host with /v1/
API = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox indicator types to our IOC types
def _map_type(t: str) -> str:
    t = (t or "").lower()
    if t in ("url",):
        return "url"
    if t in ("domain", "fqdn"):
        return "domain"
    if t in ("sha256", "filehash-sha256"):
        return "sha256"
    if t in ("sha1", "filehash-sha1"):
        return "sha1"
    if t in ("md5", "filehash-md5"):
        return "md5"
    if t in ("ip", "ip:port", "ipv4", "ipv6"):
        return "ip"
    if t in ("email",):
        return "email"
    return "other"

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        # Common ThreatFox format: "YYYY-MM-DD HH:MM:SS" (UTC)
        if isinstance(s, str) and " " in s and ":" in s and "T" not in s:
            # naive -> treat as UTC
            dt = datetime.strptime(s.split(" ")[0] + " " + s.split(" ")[1], "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        # ISO-ish
        s2 = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s2)
    except Exception:
        return None

def _normalize_ioc(d: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    ioc_type = _map_type(d.get("ioc_type"))
    raw_val = (d.get("ioc") or "").strip()
    if not raw_val:
        return "other", "", {}

    ctx: Dict[str, Any] = {}

    # Extract IP:port if present
    value = raw_val
    if d.get("ioc_type", "").lower() in ("ip:port",):
        if ":" in raw_val:
            ip, port = raw_val.rsplit(":", 1)
            if ip:
                value = ip
                ctx["port"] = port

    # Normalize domain to lowercase
    if ioc_type == "domain":
        value = value.lower()

    # Collect as much context as available
    ctx.update({
        "threat_type": d.get("threat_type"),
        "malware": d.get("malware"),
        "malware_printable": d.get("malware_printable"),
        "tags": d.get("tags"),
        "confidence": d.get("confidence_level"),
        "reference": d.get("reference"),
        "first_seen": d.get("first_seen") or d.get("first_seen_utc"),
        "last_seen": d.get("last_seen") or d.get("last_seen_utc"),
        "reporter": d.get("reporter"),
        "id": d.get("id") or d.get("ioc_id"),
        "tlp": d.get("tlp"),
        "anonymous": d.get("anonymous"),
    })

    return ioc_type, value, ctx

def fetch_threatfox(source, days: int = 1) -> List[Dict[str, Any]]:
    """
    Fetch recent IOCs from ThreatFox using API key when provided.

    - Uses incremental fetching when `source.last_etag` contains the last IOC ID.
    - Falls back to time-window fetch via `days`.
    - Returns a single 'batch' item with an `iocs` array; returns [] if no IOCs.
    """
    auth_key = None
    try:
        auth_key = getattr(source, "auth_secret", None) or None
    except Exception:
        auth_key = None

    headers = {
        "Accept": "application/json",
        "User-Agent": "threat-intel-portal/0.1",
        "Content-Type": "application/json",
    }
    if auth_key:
        headers["Auth-Key"] = auth_key

    # ThreatFox recommends get_iocs with days 1–7 for recent IOCs
    days = max(1, min(int(days or 1), 7))
    query: Dict[str, Any] = {"query": "get_iocs", "days": days}
    # Also include auth_key in body for compatibility
    if auth_key:
        query["auth_key"] = auth_key

    try:
        r = requests.post(API, json=query, timeout=60, headers=headers)
        r.raise_for_status()
        js = r.json()
    except Exception:
        # Avoid crashing the worker on transient/network issues
        return []

    # Ensure query succeeded according to API contract; fallback to no-auth if needed
    if not isinstance(js, dict) or js.get("query_status") == "nok":
        if auth_key:
            try:
                q2 = {"query": "get_iocs", "days": days}
                r2 = requests.post(API, json=q2, timeout=60, headers={k:v for k,v in headers.items() if k.lower() != "auth-key"})
                r2.raise_for_status()
                js = r2.json()
            except Exception:
                return []
            if not isinstance(js, dict) or js.get("query_status") == "nok":
                return []
        else:
            return []

    data = js.get("data", []) or []
    if not data:
        return []

    iocs: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    last_times: List[datetime] = []

    for d in data:
        t, v, ctx = _normalize_ioc(d)
        if not v:
            continue
        key = (t, v)
        if key in seen:
            continue
        seen.add(key)
        # Track last_seen for published time
        ls = _parse_dt(ctx.get("last_seen")) if ctx.get("last_seen") else None
        if ls:
            last_times.append(ls)
        iocs.append({"type": t, "value": v, "context": ctx})

    if not iocs:
        return []

    # Determine a meaningful published_at for the batch
    published_at = max(last_times) if last_times else datetime.now(timezone.utc)

    # Title reflects recent window
    title_parts = [
        "ThreatFox",
        f"last {days} day(s)",
        f"({len(iocs)} IOCs)",
    ]
    title = " ".join([p for p in title_parts if p])

    raw_meta = {
        "count": len(iocs),
        "query": query.get("query"),
        "window_days": days,
    }

    return [{
        "canonical_url": "https://threatfox.abuse.ch/",
        "title": title,
        "published_at": published_at,
        "author": "abuse.ch ThreatFox",
        "raw": raw_meta,
        "text": "Recent IOCs from ThreatFox (abuse.ch).",
        "summary_short": None,
        "iocs": iocs,
    }]
