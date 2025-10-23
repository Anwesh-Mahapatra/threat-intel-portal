#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/srv/threat-intel-portal
cd "$APP_DIR"

# sanity: .env must live on server (never in git)
if [[ ! -f .env ]]; then
  echo "[deploy] ERROR: /srv/threat-intel-portal/.env missing. Create it once on the server."
  exit 1
fi

# venv + deps
python3 -m venv .venv || true
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r api/requirements.txt
pip install jinja2==3.1.4

# seed (idempotent)
cd "$APP_DIR/api"
python -m app.seed || true

# restart services (sudo NOPASSWD set up already)
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl restart ti-api ti-worker ti-beat

echo "[deploy] done"