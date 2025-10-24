#!/usr/bin/env bash
set -euo pipefail
set -x

APP_DIR=/srv/threat-intel-portal

# 0) .env must exist on the server (kept out of git)
test -f "$APP_DIR/.env"

# 1) venv + deps
cd "$APP_DIR"
python3 -m venv .venv || true
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r api/requirements.txt
pip install jinja2==3.1.4

# 2) seed with CWD at repo root so pydantic reads .env here
PYTHONPATH=api python -m app.seed || true

# 3) restart services with EXACT unit names (matches sudoers)
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl restart ti-api.service
sudo /usr/bin/systemctl restart ti-worker.service
sudo /usr/bin/systemctl restart ti-beat.service

echo "[deploy] done"