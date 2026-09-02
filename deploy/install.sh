#!/usr/bin/env bash
# Install or update the platform on a Linux VM (Debian/Ubuntu; adapt the apt commands
# for RHEL). Run as root from a clone of the repository:
#   sudo bash deploy/install.sh
# Idempotent: re-running after a git pull updates the code, dependencies and frontend.

set -euo pipefail

APP_DIR=/opt/sherlock
DATA_DIR=/var/lib/sherlock
CONF_DIR=/etc/sherlock
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "== Service user and directory tree"
id sherlock >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin sherlock
mkdir -p "$APP_DIR" "$DATA_DIR" "$CONF_DIR/tls"
chown sherlock:sherlock "$DATA_DIR" && chmod 700 "$DATA_DIR"

echo "== Python interpreter (3.11 minimum)"
PYTHON=""
for candidate in python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done
if [ -z "$PYTHON" ]; then
    echo "Python 3.11+ not found: install python3.11 (or 3.12) and python3.11-venv." >&2
    exit 1
fi

echo "== Copying code to $APP_DIR"
rsync -a --delete \
    --exclude '.git' --exclude '.venv' --exclude 'node_modules' --exclude '.env' \
    --exclude '.secrets*' --exclude '*.db' --exclude 'backup-*' \
    "$SRC_DIR/" "$APP_DIR/"

echo "== Python dependencies"
[ -d "$APP_DIR/.venv" ] || "$PYTHON" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet "$APP_DIR"

echo "== Frontend"
if command -v npm >/dev/null 2>&1; then
    (cd "$APP_DIR/web" && npm ci --silent && npm run build --silent)
else
    echo "npm not found: build the frontend elsewhere (npm run build) and copy web/dist here." >&2
fi
chown -R sherlock:sherlock "$APP_DIR"

echo "== Configuration"
if [ ! -f "$CONF_DIR/sherlock.env" ]; then
    cp "$SRC_DIR/deploy/sherlock.env.example" "$CONF_DIR/sherlock.env"
    KEY="$("$APP_DIR/.venv/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    sed -i "s|^SHL_SECRET_STORE_KEY=.*|SHL_SECRET_STORE_KEY=$KEY|" "$CONF_DIR/sherlock.env"
    echo "   -> $CONF_DIR/sherlock.env created with a generated store key: fill in the variables."
fi
chown root:sherlock "$CONF_DIR/sherlock.env" && chmod 640 "$CONF_DIR/sherlock.env"

echo "== systemd service"
cp "$SRC_DIR/deploy/sherlock.service" /etc/systemd/system/sherlock.service
systemctl daemon-reload
systemctl enable sherlock >/dev/null
systemctl restart sherlock

echo "== Nginx"
if [ -d /etc/nginx/sites-available ] && [ ! -f /etc/nginx/sites-available/sherlock ]; then
    cp "$SRC_DIR/deploy/nginx-sherlock.conf" /etc/nginx/sites-available/sherlock
    echo "   -> /etc/nginx/sites-available/sherlock installed: set server_name and the"
    echo "      certificate, then: ln -s /etc/nginx/sites-available/sherlock /etc/nginx/sites-enabled/"
    echo "      and nginx -t && systemctl reload nginx"
fi

echo
echo "Done. Service status:"
systemctl --no-pager --lines=5 status sherlock || true
echo
echo "First admin account (one-time):"
echo "  sudo -u sherlock env \$(grep -v '^#' $CONF_DIR/sherlock.env | xargs) \\"
echo "    $APP_DIR/.venv/bin/python $APP_DIR/scripts/create_account.py <username> --roles analyst,admin"
