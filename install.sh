#!/usr/bin/env bash
set -Eeuo pipefail

REPO_RAW_BASE="${REPO_RAW_BASE:-https://raw.githubusercontent.com/ach1992/marzban-watcher/main}"
APP_DIR="/opt/marzban-watcher"
ENV_FILE="/etc/marzban-watcher.env"
SERVICE_FILE="/etc/systemd/system/marzban-watcher.service"
BIN_FILE="/usr/local/bin/marzban-watcher"
COMPAT_BIN="/usr/local/bin/marzwatch"
LOG_FILE="/var/log/marzban-watcher-install.log"
DATA_DIR="/var/lib/marzban-watcher"
STDOUT_LOG="/var/log/marzban-watcher.stdout.log"
STDERR_LOG="/var/log/marzban-watcher.stderr.log"
OFFLINE=0

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
  esac
done

mkdir -p /var/log
exec > >(tee -a "$LOG_FILE") 2>&1

on_error() {
  local line="$1"
  echo
  echo "[ERROR] Installation failed at line $line"
  echo "[ERROR] See full log: $LOG_FILE"
}
trap 'on_error $LINENO' ERR

banner() {
  cat <<'EOF'
============================================================
 __  __                     _                     __        __    _       _
|  \/  | __ _ _ __ ______ _| |__   __ _ _ __      \ \      / /_ _| |_ ___| |__   ___ _ __
| |\/| |/ _` | '__|_  / _` | '_ \ / _` | '_ \      \ \ /\ / / _` | __/ __| '_ \ / _ \ '__|
| |  | | (_| | |   / / (_| | |_) | (_| | | | |      \ V  V / (_| | || (__| | | |  __/ |
|_|  |_|\__,_|_|  /___\__,_|_.__/ \__,_|_| |_|       \_/\_/ \__,_|\__\___|_| |_|\___|_|
============================================================
Managed installer for Marzban Watcher
Install log: /var/log/marzban-watcher-install.log
EOF
}

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Please run this installer as root."
    exit 1
  fi
}

ask_default() {
  local prompt="$1"
  local default="$2"
  local var
  read -r -p "$prompt [$default]: " var
  if [[ -z "$var" ]]; then
    printf '%s' "$default"
  else
    printf '%s' "$var"
  fi
}

ask_secret() {
  local prompt="$1"
  local var
  read -r -s -p "$prompt: " var
  echo
  printf '%s' "$var"
}

sanitize_single_line() {
  printf '%s' "$1" | tr -d '\r\n'
}

require_nonempty() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "[ERROR] $name cannot be empty."
    exit 1
  fi
}

normalize_base_url() {
  printf '%s' "$1" | sed -E 's#/[Hh][Pp][Aa][Nn][Ee][Ll]/?$##; s#/$##'
}

fetch_or_copy() {
  local src_name="$1"
  local dest="$2"
  if [[ $OFFLINE -eq 1 || -f "./$src_name" ]]; then
    cp "./$src_name" "$dest"
  else
    curl -fsSL "$REPO_RAW_BASE/$src_name" -o "$dest"
  fi
}

write_env() {
  cat > "$ENV_FILE" <<EOF
BASE_URL=$(sanitize_single_line "$BASE_URL")
ADMIN_USER=$(sanitize_single_line "$ADMIN_USER")
ADMIN_PASS=$(sanitize_single_line "$ADMIN_PASS")
REFRESH=$(sanitize_single_line "$REFRESH")
LIVE_WINDOW=$(sanitize_single_line "$LIVE_WINDOW")
LIVE_IP_LIMIT=$(sanitize_single_line "$LIVE_IP_LIMIT")
LIVE_CONN_LIMIT=$(sanitize_single_line "$LIVE_CONN_LIMIT")
LIVE_TOP=$(sanitize_single_line "$LIVE_TOP")
HOURLY_WINDOW=$(sanitize_single_line "$HOURLY_WINDOW")
HOURLY_IP_LIMIT=$(sanitize_single_line "$HOURLY_IP_LIMIT")
HOURLY_CONN_LIMIT=$(sanitize_single_line "$HOURLY_CONN_LIMIT")
INSECURE=$(sanitize_single_line "$INSECURE")
EOF
  chmod 600 "$ENV_FILE"
}

main() {
  require_root
  banner
  echo "[INFO] Installing dependencies..."
  apt update
  apt install -y python3 python3-venv procps curl ca-certificates

  echo
  BASE_URL="$(ask_default 'Base URL (do not include /hpanel)' 'https://panel.example.com:8443')"
  BASE_URL="$(normalize_base_url "$BASE_URL")"
  ADMIN_USER="$(sanitize_single_line "$(ask_default 'Admin username' 'admin')")"
  ADMIN_PASS="$(sanitize_single_line "$(ask_secret 'Admin password')")"
  require_nonempty 'Admin username' "$ADMIN_USER"
  require_nonempty 'Admin password' "$ADMIN_PASS"
  REFRESH="$(ask_default 'Refresh seconds' '10')"
  LIVE_WINDOW="$(ask_default 'Live window seconds' '300')"
  LIVE_IP_LIMIT="$(ask_default 'Live unique IP limit' '3')"
  LIVE_CONN_LIMIT="$(ask_default 'Live connection limit' '40')"
  LIVE_TOP="$(ask_default 'Max rows in live report' '50')"
  HOURLY_WINDOW="$(ask_default 'Hourly window seconds' '3600')"
  HOURLY_IP_LIMIT="$(ask_default 'Hourly unique IP limit' '4')"
  HOURLY_CONN_LIMIT="$(ask_default 'Hourly connection limit' '250')"
  INSECURE=""

  mkdir -p "$APP_DIR" "$DATA_DIR"
  touch "$STDOUT_LOG" "$STDERR_LOG"

  echo "[INFO] Fetching application files..."
  fetch_or_copy "marzban_watch.py" "$APP_DIR/marzban_watch.py"
  fetch_or_copy "marzban-watcher" "$BIN_FILE"
  fetch_or_copy "marzban-watcher.service" "$SERVICE_FILE"
  fetch_or_copy "uninstall.sh" "$APP_DIR/uninstall.sh"
  fetch_or_copy "requirements.txt" "$APP_DIR/requirements.txt"

  chmod 700 "$APP_DIR/marzban_watch.py"
  chmod +x "$BIN_FILE" "$APP_DIR/uninstall.sh"
  ln -sf "$BIN_FILE" "$COMPAT_BIN"

  echo "[INFO] Creating virtual environment..."
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --upgrade pip
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

  echo "[INFO] Writing environment file..."
  write_env

  echo "[INFO] Enabling service..."
  systemctl daemon-reload
  systemctl enable --now marzban-watcher
  systemctl restart marzban-watcher
  sleep 3
  if ! systemctl is-active --quiet marzban-watcher; then
    echo "[ERROR] Service did not start successfully."
    echo "[ERROR] Check: systemctl status marzban-watcher --no-pager -l"
    echo "[ERROR] Check: tail -n 100 /var/log/marzban-watcher.stderr.log"
    exit 1
  fi

  echo
  echo "[OK] Marzban Watcher installed successfully."
  echo "[OK] Command: marzban-watcher"
  echo "[OK] Old compatibility command: marzwatch"
  echo "[OK] Service: systemctl status marzban-watcher --no-pager -l"
  echo "[OK] Install log: $LOG_FILE"
}

main "$@"
