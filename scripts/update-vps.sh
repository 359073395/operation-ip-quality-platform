#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="operation-ip-quality-platform"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
PORT="${PORT:-4173}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root. Example: sudo bash scripts/update-vps.sh"
  exit 1
fi

cd "${APP_DIR}"
git pull --ff-only
npm ci --omit=dev
PORT="${PORT}" pm2 restart "${APP_NAME}" --update-env
pm2 save

echo "Update complete."
