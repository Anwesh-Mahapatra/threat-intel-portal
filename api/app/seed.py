from sqlalchemy.orm import Session
from sqlalchemy import select
from .db import SessionLocal, init_db
from .models import Source
from .settings import settings

def ensure_source(db: Session, name: str, kind: str, endpoint: str, interval: int = 900, auth_secret: str | None = None):
    existing = db.execute(select(Source).where(Source.name==name)).scalar_one_or_none()
    if existing:
        # Update in place if anything changed so seeds converge
        changed = False
        if existing.kind != kind:
            existing.kind = kind; changed = True
        if existing.endpoint != endpoint:
            existing.endpoint = endpoint; changed = True
        if auth_secret and existing.auth_secret != auth_secret:
            existing.auth_secret = auth_secret; changed = True
        if interval and existing.poll_interval_seconds != interval:
            existing.poll_interval_seconds = interval; changed = True
        if changed:
            db.add(existing); db.commit(); db.refresh(existing)
        return existing
    s = Source(
        name=name,
        kind=kind,
        endpoint=endpoint,
        poll_interval_seconds=interval,
        enabled=True,
        auth_secret=auth_secret,
    )
    db.add(s); db.commit(); db.refresh(s)
    return s

def main():
    init_db()
    db = SessionLocal()
    try:
        ensure_source(db, "CISA KEV", "json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 3600)
        ensure_source(db, "MSRC SUG RSS", "rss", "https://api.msrc.microsoft.com/update-guide/rss", 900)
        ensure_source(db, "The DFIR Report", "rss", "https://thedfirreport.com/feed/", 900)
        # ThreatFox – uses API key if provided
        ensure_source(
            db,
            "ThreatFox",
            "threatfox",
            "https://threatfox-api.abuse.ch/api/v1/",
            900,
            auth_secret=(settings.THREATFOX_AUTH_KEY or settings.THREATFOX_API_KEY or None),
        )
        print("Seeded sources ✔")
    finally:
        db.close()

if __name__ == "__main__":
    main()
