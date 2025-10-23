from celery import Celery
from datetime import datetime
from sqlalchemy.orm import Session
from .settings import settings
from .db import SessionLocal
from .ingest.rss import fetch_rss
from .ingest.cisa_kev import fetch_cisa_kev
from .ingest.threatfox import fetch_threatfox
from .ingest.threatfox_export import iter_full_export, build_chunks, make_batch_item
from .models import Source, Item, IOC
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
    "threatfox-15min": {
        "task": "app.workers.task_fetch_threatfox",
        "schedule": 15*60
    },
}

def schedule_now():
    task_fetch_rss.delay()
    task_fetch_kev.delay()
    task_fetch_threatfox.delay()

def _upsert_items(db: Session, normalized_items: list[dict], source_id: int):
    for n in normalized_items:
        # Simple dedup hash
        raw = (n.get("title","") + (n.get("canonical_url","") or "")).encode()
        h = hashlib.sha256(raw).digest()
        exists = db.execute(select(Item.id).where(Item.hash_sha256==h).limit(1)).scalar_one_or_none()
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
        # If this item carries IOCs, persist them linked to this item
        iocs = n.get("iocs") or []
        if iocs:
            db.flush()  # ensure it.id is available
            for i in iocs:
                try:
                    io = IOC(item_id=it.id, type=i.get("type"), value=i.get("value"), context=i.get("context"))
                    db.add(io)
                except Exception:
                    # Skip malformed entries rather than failing the batch
                    continue
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

@celery_app.task(name="app.workers.task_fetch_threatfox")
def task_fetch_threatfox():
    db = SessionLocal()
    try:
        tf_sources = db.execute(select(Source).where(Source.kind=="threatfox", Source.enabled==True)).scalars().all()
        for s in tf_sources:
            # Use a conservative recent window per TF guidance
            items = fetch_threatfox(s, days=3)
            if not items:
                print("ThreatFox: fetch returned 0 items")
                continue
            ioc_count = sum(len(n.get("iocs") or []) for n in items)
            print(f"ThreatFox: fetched {len(items)} batch item(s), {ioc_count} IOCs")
            _upsert_items(db, items, s.id)
    finally:
        db.close()

@celery_app.task(name="app.workers.task_threatfox_backfill_full")
def task_threatfox_backfill_full():
    import os
    db = SessionLocal()
    total = 0
    try:
        src = db.execute(
            select(Source).where(Source.kind=="threatfox", Source.name.ilike("%ThreatFox%"))
        ).scalar_one_or_none()
        if not src:
            return "no ThreatFox source found"

        for chunk in build_chunks(iter_full_export(), size=500):
            batch = make_batch_item(count=len(chunk))
            it = Item(
                source_id=src.id,
                canonical_url=batch["canonical_url"],
                title=batch["title"],
                published_at=batch["published_at"],
                fetched_at=datetime.utcnow(),
                author=batch["author"],
                raw=batch["raw"],
                text=batch["text"],
                summary_short=batch["summary_short"],
                lang="en",
                hash_sha256=os.urandom(32)
            )
            db.add(it)
            db.flush()
            for ioc in chunk:
                t = (ioc.get("type") or "").lower()
                if t not in ("ip","domain","url","sha256","sha1","md5","email"):
                    continue
                db.add(IOC(item_id=it.id, type=t, value=ioc.get("value"), context=ioc.get("context")))
            db.commit()
            total += len(chunk)
        return f"backfill done: {total} IOCs"
    finally:
        db.close()
