#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/home/zgy/Desktop/Agent_Work_Path/SentinelAI_html"
ENV_FILE="/etc/sentinelai-html.env"
SERVICE_FILE="/etc/systemd/system/sentinelai-html.service"

if [[ ! -f "${APP_DIR}/web_app.py" || ! -f "${APP_DIR}/requirements.txt" ]]; then
  echo "HTML 版本目录不完整" >&2
  exit 2
fi

if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  python3 -m venv "${APP_DIR}/.venv"
fi
"${APP_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r "${APP_DIR}/requirements.lock.txt"
install -d -m 700 "${APP_DIR}/data" "${APP_DIR}/data/reports" "${APP_DIR}/uploads"

if ! sudo test -f "${ENV_FILE}"; then
  SECRET_KEY="$(openssl rand -hex 32)"
  printf 'APP_SECRET_KEY=%s\n' "${SECRET_KEY}" | sudo tee "${ENV_FILE}" >/dev/null
  sudo chmod 600 "${ENV_FILE}"
fi

sudo install -o root -g root -m 644 "${APP_DIR}/deploy/sentinelai-html.service" "${SERVICE_FILE}"
sudo systemctl daemon-reload
sudo systemctl enable sentinelai-html.service
sudo systemctl restart sentinelai-html.service
curl --noproxy '*' --fail --silent --show-error --retry 24 --retry-connrefused --retry-delay 2 http://127.0.0.1:8502/
