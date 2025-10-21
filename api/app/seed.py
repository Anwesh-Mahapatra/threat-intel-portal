from sqlalchemy.orm import Session
from sqlalchemy import select
from .db import SessionLocal, init_db
from .models import Source

def ensure_source(db: Session, name: str, kind: str, endpoint: str, interval: int = 900):
    existing = db.execute(select(Source).where(Source.name==name)).scalar_one_or_none()
    if existing:
        return existing
    s = Source(name=name, kind=kind, endpoint=endpoint, poll_interval_seconds=interval, enabled=True)
    db.add(s); db.commit(); db.refresh(s)
    return s

def main():
    init_db()
    db = SessionLocal()
    try:
        ensure_source(db, "CISA KEV", "json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 3600)
        ensure_source(db, "MSRC SUG RSS", "rss", "https://api.msrc.microsoft.com/update-guide/rss", 900)
        ensure_source(db, "The DFIR Report", "rss", "https://thedfirreport.com/feed/", 900)
        print("Seeded sources ✔")
    finally:
        db.close()

if __name__ == "__main__":
    main()
