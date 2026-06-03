#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="operation-ip-quality-platform"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
PORT="${PORT:-4173}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
REPO_URL="${1:-${REPO_URL:-}}"

if [[ -z "${REPO_URL}" ]]; then
  echo "Usage: sudo PORT=4173 bash deploy-vps.sh https://github.com/your-name/your-repo.git"
  echo "Or: curl -fsSL https://raw.githubusercontent.com/your-name/your-repo/main/scripts/deploy-vps.sh | sudo bash -s -- https://github.com/your-name/your-repo.git"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root. Example: sudo bash scripts/deploy-vps.sh ${REPO_URL}"
  exit 1
fi

echo "==> Installing system packages"
apt-get update
apt-get install -y ca-certificates curl git ufw

if ! command -v node >/dev/null 2>&1; then
  echo "==> Installing Node.js 22"
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

echo "==> Installing PM2"
npm install -g pm2

echo "==> Fetching project"
if [[ -d "${APP_DIR}/.git" ]]; then
  git -C "${APP_DIR}" fetch --all --prune
  DEFAULT_BRANCH="$(git -C "${APP_DIR}" remote show origin | awk '/HEAD branch/ {print $NF}')"
  git -C "${APP_DIR}" reset --hard "origin/${DEFAULT_BRANCH:-main}"
else
  rm -rf "${APP_DIR}"
  git clone "${REPO_URL}" "${APP_DIR}"
fi

cd "${APP_DIR}"

echo "==> Installing dependencies"
npm ci --omit=dev

echo "==> Writing environment"
touch .env

set_env_value() {
  local key="$1"
  local value="$2"

  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    printf '%s=%s\n' "${key}" "${value}" >> .env
  fi
}

set_env_value "PORT" "${PORT}"

if [[ -z "${ADMIN_PASSWORD}" ]]; then
  if grep -q '^ADMIN_PASSWORD=.' .env; then
    echo "==> Admin password already configured"
  else
    echo "==> Configure admin password"
    read -r -s -p "Enter admin password for /admin: " ADMIN_PASSWORD
    echo
    if [[ -z "${ADMIN_PASSWORD}" ]]; then
      ADMIN_PASSWORD="$(node -e "console.log(require('crypto').randomBytes(12).toString('hex'))")"
      echo "No password entered. Generated admin password: ${ADMIN_PASSWORD}"
      echo "Please save this password now."
    fi
    set_env_value "ADMIN_PASSWORD" "${ADMIN_PASSWORD}"
  fi
else
  set_env_value "ADMIN_PASSWORD" "${ADMIN_PASSWORD}"
fi

echo "==> Starting service"
PORT="${PORT}" pm2 start ecosystem.config.cjs --update-env
pm2 save

echo "==> Enabling PM2 startup"
pm2 startup systemd -u root --hp /root || true

echo "==> Opening firewall port ${PORT}"
ufw allow "${PORT}/tcp" || true

PUBLIC_IP="$(curl -fsSL https://api.ipify.org || hostname -I | awk '{print $1}')"

echo
echo "Deployment complete."
echo "App directory: ${APP_DIR}"
echo "Service name: ${APP_NAME}"
echo "URL: http://${PUBLIC_IP}:${PORT}"
echo
echo "Useful commands:"
echo "  pm2 status"
echo "  pm2 logs ${APP_NAME}"
echo "  pm2 restart ${APP_NAME}"
