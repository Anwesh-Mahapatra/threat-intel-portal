#!/usr/bin/env bash
set -euo pipefail
set -x

APP_DIR=/srv/threat-intel-portal

# .env must live on the server
test -f "$APP_DIR/.env"

# venv + deps
cd "$APP_DIR"
python3 -m venv .venv || true
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r api/requirements.txt
pip install jinja2==3.1.4

# export .env so SQLAlchemy gets localhost, not "db"
set -a
. "$APP_DIR/.env"
set +a

# run seed from repo root with PYTHONPATH set
PYTHONPATH=api python -m app.seed   # (no '|| true' here)

# restart services (exact unit names match sudoers)
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl restart ti-api.service
sudo /usr/bin/systemctl restart ti-worker.service
sudo /usr/bin/systemctl restart ti-beat.service

echo "[deploy] done"
