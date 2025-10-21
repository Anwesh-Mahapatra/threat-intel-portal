from fastapi import FastAPI, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from datetime import datetime
from .db import SessionLocal, init_db
from .search import search_items
from .templates import render
from .workers import schedule_now  # for manual triggers
from . import workers

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

@app.post("/admin/refresh")
def admin_refresh():
    # Kick off immediate fetch tasks
    schedule_now()
    return {"status": "scheduled"}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
