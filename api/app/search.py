# Minimal search shim – in MVP we just read from DB and allow future Meilisearch wiring.
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from .models import Item, Source

def search_items(db: Session, q: str | None = None, limit: int = 50):
    stmt = select(Item, Source.name).join(Source, Item.source_id == Source.id).order_by(desc(Item.published_at)).limit(limit)
    rows = db.execute(stmt).all()
    out = []
    for it, sname in rows:
        out.append({
            "id": it.id,
            "title": it.title,
            "canonical_url": it.canonical_url,
            "published_at": it.published_at.isoformat() if it.published_at else None,
            "source": sname,
            "summary_short": it.summary_short
        })
    return out, len(out)
