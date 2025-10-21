import requests, feedparser
from bs4 import BeautifulSoup
from datetime import datetime
from email.utils import parsedate_to_datetime

def fetch_rss(source):
    headers = {}
    if source.last_etag:
        headers["If-None-Match"] = source.last_etag
    r = requests.get(source.endpoint, timeout=30, headers=headers)
    if r.status_code == 304:
        return []
    try:
        etag = r.headers.get("ETag")
    except Exception:
        etag = None

    feed = feedparser.parse(r.content)
    out = []
    for e in feed.entries:
        url = e.get("link")
        title = e.get("title")
        published_raw = e.get("published") or e.get("updated")
        try:
            published_at = parsedate_to_datetime(published_raw) if published_raw else None
        except Exception:
            published_at = None
        html = e.get("summary", "")
        for c in e.get("content", []):
            if isinstance(c, dict) and "value" in c:
                html = c["value"]
        text = BeautifulSoup(html, "lxml").get_text("\n")
        out.append({
            "canonical_url": url,
            "title": title,
            "published_at": published_at,
            "author": e.get("author"),
            "raw": {"entry": e},
            "text": text,
            "summary_short": None
        })
    return out
