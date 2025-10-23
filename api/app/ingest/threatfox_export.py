import io, json, tempfile, zipfile, requests
from datetime import datetime, timezone
import ijson

EXPORT_FULL = "https://threatfox.abuse.ch/export/json/full/"  # zip; see docs
# You can swap to the “recent additions” export if you only want 48h:
# EXPORT_RECENT = "https://threatfox.abuse.ch/export/json/recent/"

def _map_type(t: str) -> str:
    t = (t or "").lower()
    if t == "url": return "url"
    if t in ("domain","fqdn"): return "domain"
    if t in ("ip","ipv4","ipv6","ip:port"): return "ip"
    if t in ("filehash-sha256","sha256"): return "sha256"
    if t in ("filehash-sha1","sha1"): return "sha1"
    if t in ("filehash-md5","md5"): return "md5"
    return "other"

def _ioc_context(d: dict) -> dict:
    return {
        "threat_type": d.get("threat_type"),
        "threat_type_desc": d.get("threat_type_desc"),
        "malware": d.get("malware"),
        "malware_printable": d.get("malware_printable"),
        "malware_alias": d.get("malware_alias"),
        "malpedia": d.get("malware_malpedia"),
        "confidence": d.get("confidence_level"),
        "first_seen": d.get("first_seen"),
        "last_seen": d.get("last_seen"),
        "reporter": d.get("reporter"),
        "reference": d.get("reference"),
        "tags": d.get("tags"),
        "ioc_id": d.get("id"),
    }

def iter_full_export(timeout=600):
    # Download to a temp file to avoid memory spikes, then stream parse JSON array
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with requests.get(EXPORT_FULL, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            for chunk in r.iter_content(1024*64):
                if chunk: tmp.write(chunk)
        tmp.flush()
        with zipfile.ZipFile(tmp.name) as zf:
            name = zf.namelist()[0]
            with zf.open(name) as jf:
                for obj in ijson.items(jf, "item"):
                    val = obj.get("ioc")
                    if not val: 
                        continue
                    yield {
                        "type": _map_type(obj.get("ioc_type")),
                        "value": val,
                        "context": _ioc_context(obj),
                    }

def build_chunks(it, size=500):
    buf = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf

def make_batch_item(count: int):
    now = datetime.now(timezone.utc)
    return {
        "canonical_url": "https://threatfox.abuse.ch/",
        "title": f"ThreatFox full export — {count} IOCs",
        "published_at": now,
        "author": "abuse.ch ThreatFox",
        "raw": {"source": "export-json-full", "count": count},
        "text": "Full export backfill (last ~6 months per TF policy).",
        "summary_short": None,
        # we'll attach iocs per chunk in the worker
    }

