# Threat Intel Portal (Starter)

A minimal, no-frills MVP to aggregate threat intel feeds into a single web UI:

- **Backend**: FastAPI (Python 3.11)
- **Workers**: Celery + Celery Beat (scheduled jobs)
- **DB**: PostgreSQL
- **Cache/Queue**: Redis
- **Search (optional)**: Meilisearch (faceted search)
- **UI**: Simple Jinja templates (home, items list, item details)

## Quickstart

1) Install Docker + Docker Compose plugin on your Ubuntu host.

2) Copy `.env.example` to `.env` and edit values (keep defaults for local dev).

3) Start everything:
```bash
docker compose up -d --build
```

4) Initialize feeds (run once):
```bash
docker compose exec api python -m app.seed
```

5) Open the site:
- API docs: http://localhost:8000/docs
- Web UI:   http://localhost:8000/

## Default sources included

- CISA KEV (JSON)
- MSRC Security Update Guide (RSS)
- The DFIR Report (RSS)

You can add more feeds via the DB (table `sources`) or extend ingestors in `app/ingest/`.

## Useful commands

Bring logs:
```bash
docker compose logs -f api worker beat
```

Recreate from scratch:
```bash
docker compose down -v
docker compose up -d --build
```

## Dev notes

- Tables are auto-created on API startup.
- Celery Beat schedules periodic fetching (15 min RSS, 60 min JSON by default).
- Meilisearch is included but optional; API will still work if it isn’t ready.
