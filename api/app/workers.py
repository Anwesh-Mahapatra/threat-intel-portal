from celery import Celery
from datetime import datetime
from sqlalchemy.orm import Session
from .settings import settings
from .db import SessionLocal
from .ingest.rss import fetch_rss
from .ingest.cisa_kev import fetch_cisa_kev
from .models import Source, Item
from sqlalchemy import select
from bs4 import BeautifulSoup
import hashlib

celery_app = Celery(__name__, broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.timezone = "UTC"

# Schedules
celery_app.conf.beat_schedule = {
    "rss-every-15min": {
        "task": "app.workers.task_fetch_rss",
        "schedule": 15*60
    },
    "kev-hourly": {
        "task": "app.workers.task_fetch_kev",
        "schedule": 60*60
    },
}

def schedule_now():
    task_fetch_rss.delay()
    task_fetch_kev.delay()

def _upsert_items(db: Session, normalized_items: list[dict], source_id: int):
    for n in normalized_items:
        # Simple dedup hash
        raw = (n.get("title","") + (n.get("canonical_url","") or "")).encode()
        h = hashlib.sha256(raw).digest()
        exists = db.execute(select(Item).where(Item.hash_sha256==h)).scalar_one_or_none()
        if exists: 
            continue
        it = Item(
            source_id=source_id,
            canonical_url=n.get("canonical_url"),
            title=n.get("title"),
            published_at=n.get("published_at"),
            fetched_at=datetime.utcnow(),
            author=n.get("author"),
            raw=n.get("raw"),
            text=n.get("text"),
            hash_sha256=h,
            summary_short=n.get("summary_short"),
            lang="en"
        )
        db.add(it)
    db.commit()

@celery_app.task(name="app.workers.task_fetch_rss")
def task_fetch_rss():
    db = SessionLocal()
    try:
        rss_sources = db.execute(select(Source).where(Source.kind=="rss", Source.enabled==True)).scalars().all()
        for s in rss_sources:
            items = fetch_rss(s)
            _upsert_items(db, items, s.id)
    finally:
        db.close()

@celery_app.task(name="app.workers.task_fetch_kev")
def task_fetch_kev():
    db = SessionLocal()
    try:
        kev_sources = db.execute(select(Source).where(Source.kind=="json", Source.name.ilike("%CISA KEV%"))).scalars().all()
        for s in kev_sources:
            items = fetch_cisa_kev(s)
            _upsert_items(db, items, s.id)
    finally:
        db.close()
