from fastapi import FastAPI, Depends, Query, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from datetime import datetime
from .db import SessionLocal, init_db
from .search import search_items
from .templates import render
from .workers import schedule_now  # for manual triggers
from . import workers
from sqlalchemy import select
from .models import Item, Source, IOC

app = FastAPI(title="Threat Intel Portal")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home(db: Session = Depends(get_db)):
    items, _ = search_items(db, limit=50)
    return render("index.html", {"items": items})

@app.get("/items", response_class=HTMLResponse)
def list_items(db: Session = Depends(get_db), q: str | None = Query(None)):
    items, _ = search_items(db, q=q, limit=100)
    return render("items.html", {"items": items, "q": q})

@app.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail(item_id: int, db: Session = Depends(get_db)):
    row = db.execute(
        select(Item, Source.name).join(Source, Item.source_id == Source.id).where(Item.id == item_id)
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    item, source_name = row
    iocs = db.execute(select(IOC).where(IOC.item_id == item.id)).scalars().all()
    return render("item_detail.html", {
        "item": item,
        "source_name": source_name,
        "iocs": iocs,
    })

@app.post("/admin/refresh")
def admin_refresh():
    # Kick off immediate fetch tasks
    schedule_now()
    return {"status": "scheduled"}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
