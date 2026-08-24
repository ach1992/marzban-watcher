#!/usr/bin/env bash
set -Eeuo pipefail

REPO_RAW_BASE="${REPO_RAW_BASE:-https://raw.githubusercontent.com/ach1992/marzban-watcher/main}"
APP_DIR="/opt/marzban-watcher"
ENV_FILE="/etc/marzban-watcher.env"
SERVICE_FILE="/etc/systemd/system/marzban-watcher.service"
BIN_FILE="/usr/local/bin/marzban-watcher"
COMPAT_BIN="/usr/local/bin/marzwatch"
LOG_FILE="/var/log/marzban-watcher-install.log"
APP_LOG="/var/log/marzban-watcher.log"
DATA_DIR="/var/lib/marzban-watcher"
STDOUT_LOG="/var/log/marzban-watcher.stdout.log"
STDERR_LOG="/var/log/marzban-watcher.stderr.log"
OFFLINE=0
UPDATE=0
STAGE_DIR=""
BACKUP_DIR=""

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --update) UPDATE=1 ;;
    *)
      echo "Unknown option: $arg"
      echo "Usage: install.sh [--offline] [--update]"
      exit 2
      ;;
  esac
done

mkdir -p /var/log
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c '%s' "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]]; then
  tail -c 5242880 "$LOG_FILE" > "${LOG_FILE}.tmp" || true
  mv -f "${LOG_FILE}.tmp" "$LOG_FILE"
fi
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
  [[ -n "$STAGE_DIR" ]] && rm -rf "$STAGE_DIR"
  [[ -n "$BACKUP_DIR" ]] && rm -rf "$BACKUP_DIR"
}
trap cleanup EXIT

on_error() {
  local line="$1"
  echo
  echo "[ERROR] Installation failed at line $line"
  echo "[ERROR] See full log: $LOG_FILE"
}
trap 'on_error $LINENO' ERR

banner() {
  cat <<'BANNER'
============================================================
 __  __                     _                     __        __    _       _
| \/  | __ _ _ __ ______ _| |__   __ _ _ __      \ \      / /_ _| |_ ___| |__   ___ _ __
| |\/| |/ _` | '__|_  / _` | '_ \ / _` | '_ \      \ \ /\ / / _` | __/ __| '_ \ / _ \ '__|
| |  | | (_| | |   / / (_| | |_) | (_| | | | |      \ V  V / (_| | || (__| | | |  __/ |
|_|  |_|\__,_|_|  /___\__,_|_.__/ \__,_|_| |_|       \_/\_/ \__,_|\__\___|_| |_|\___|_|
============================================================
Managed installer for Marzban Watcher
Install log: /var/log/marzban-watcher-install.log
BANNER
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
  if [[ $OFFLINE -eq 1 ]]; then
    if [[ ! -f "./$src_name" ]]; then
      echo "[ERROR] Offline source missing: ./$src_name"
      return 1
    fi
    cp "./$src_name" "$dest"
  else
    curl -fsSL "$REPO_RAW_BASE/$src_name" -o "$dest"
  fi
}

stage_files() {
  STAGE_DIR="$(mktemp -d)"
  local name
  for name in marzban_watch.py marzban-watcher marzban-watcher.service uninstall.sh requirements.txt; do
    fetch_or_copy "$name" "$STAGE_DIR/$name"
  done

  python3 -m py_compile "$STAGE_DIR/marzban_watch.py"
  bash -n "$STAGE_DIR/marzban-watcher"
  bash -n "$STAGE_DIR/uninstall.sh"
  chmod +x "$STAGE_DIR/marzban-watcher" "$STAGE_DIR/uninstall.sh"
}

write_env() {
  cat > "$ENV_FILE" <<ENV
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
LOG_MAX_MB=64
LOG_BACKUPS=3
HISTORY_MAX_MB=512
RECONNECT_MAX_DELAY=60
LOG_REPEAT_SECONDS=300
INSECURE=$(sanitize_single_line "$INSECURE")
ENV
  chmod 600 "$ENV_FILE"
}

ensure_env_default() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

ensure_upgrade_env_defaults() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "[ERROR] Existing config not found: $ENV_FILE"
    echo "[ERROR] Run the normal installer instead of --update."
    exit 1
  fi
  chmod 600 "$ENV_FILE"
  ensure_env_default LOG_MAX_MB 64
  ensure_env_default LOG_BACKUPS 3
  ensure_env_default HISTORY_MAX_MB 512
  ensure_env_default RECONNECT_MAX_DELAY 60
  ensure_env_default LOG_REPEAT_SECONDS 300
}

atomic_replace_file() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local tmp

  tmp="$(mktemp "${destination}.new.XXXXXX")"
  if ! install -m "$mode" "$source" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv -f "$tmp" "$destination"; then
    rm -f "$tmp"
    return 1
  fi
}

install_staged_files() {
  mkdir -p "$APP_DIR" "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  cp "$STAGE_DIR/marzban_watch.py" "$APP_DIR/marzban_watch.py"
  cp "$STAGE_DIR/uninstall.sh" "$APP_DIR/uninstall.sh"
  cp "$STAGE_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  atomic_replace_file "$STAGE_DIR/marzban-watcher" "$BIN_FILE" 0755
  cp "$STAGE_DIR/marzban-watcher.service" "$SERVICE_FILE"
  chmod 700 "$APP_DIR/marzban_watch.py"
  chmod +x "$APP_DIR/uninstall.sh"
  ln -sf "$BIN_FILE" "$COMPAT_BIN"
}

backup_current_install() {
  BACKUP_DIR="$(mktemp -d)"
  [[ -f "$APP_DIR/marzban_watch.py" ]] && cp -a "$APP_DIR/marzban_watch.py" "$BACKUP_DIR/marzban_watch.py"
  [[ -f "$APP_DIR/uninstall.sh" ]] && cp -a "$APP_DIR/uninstall.sh" "$BACKUP_DIR/uninstall.sh"
  [[ -f "$APP_DIR/requirements.txt" ]] && cp -a "$APP_DIR/requirements.txt" "$BACKUP_DIR/requirements.txt"
  [[ -f "$BIN_FILE" ]] && cp -a "$BIN_FILE" "$BACKUP_DIR/marzban-watcher"
  [[ -f "$SERVICE_FILE" ]] && cp -a "$SERVICE_FILE" "$BACKUP_DIR/marzban-watcher.service"
  [[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP_DIR/marzban-watcher.env"
}

restore_backup() {
  echo "[WARN] Restoring previous installation..."
  [[ -f "$BACKUP_DIR/marzban_watch.py" ]] && cp -a "$BACKUP_DIR/marzban_watch.py" "$APP_DIR/marzban_watch.py"
  [[ -f "$BACKUP_DIR/uninstall.sh" ]] && cp -a "$BACKUP_DIR/uninstall.sh" "$APP_DIR/uninstall.sh"
  [[ -f "$BACKUP_DIR/requirements.txt" ]] && cp -a "$BACKUP_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  [[ -f "$BACKUP_DIR/marzban-watcher" ]] && atomic_replace_file "$BACKUP_DIR/marzban-watcher" "$BIN_FILE" 0755
  [[ -f "$BACKUP_DIR/marzban-watcher.service" ]] && cp -a "$BACKUP_DIR/marzban-watcher.service" "$SERVICE_FILE"
  [[ -f "$BACKUP_DIR/marzban-watcher.env" ]] && cp -a "$BACKUP_DIR/marzban-watcher.env" "$ENV_FILE"
  systemctl daemon-reload
  systemctl restart marzban-watcher || true
}

verify_service() {
  sleep 3
  if ! systemctl is-active --quiet marzban-watcher; then
    return 1
  fi
  sleep 2
  systemctl is-active --quiet marzban-watcher
}

cleanup_legacy_logs() {
  local before=0
  local after=0
  before=$(du -cb "$STDOUT_LOG" "$STDERR_LOG" 2>/dev/null | awk '/total$/ {print $1}' || true)
  before=${before:-0}

  rm -f "$STDOUT_LOG" "$STDERR_LOG" "$STDOUT_LOG".* "$STDERR_LOG".*

  after=$(du -cb "$STDOUT_LOG" "$STDERR_LOG" 2>/dev/null | awk '/total$/ {print $1}' || true)
  after=${after:-0}
  if [[ $before -gt $after ]]; then
    echo "[OK] Removed $(( (before - after) / 1024 / 1024 )) MiB of obsolete unbounded stdout/stderr logs."
  fi
}

fresh_install() {
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

  stage_files
  install_staged_files

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
  if ! verify_service; then
    echo "[ERROR] Service did not start successfully."
    echo "[ERROR] Check: systemctl status marzban-watcher --no-pager -l"
    echo "[ERROR] Check: journalctl -u marzban-watcher -n 100 --no-pager"
    exit 1
  fi

  cleanup_legacy_logs
  echo
  echo "[OK] Marzban Watcher installed successfully."
}

upgrade_install() {
  echo "[INFO] Updating existing Marzban Watcher installation..."
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "[ERROR] Existing config not found: $ENV_FILE"
    echo "[ERROR] Run the normal installer instead of --update."
    exit 1
  fi

  if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
    echo "[ERROR] Existing virtual environment not found: $APP_DIR/.venv"
    echo "[ERROR] Refusing a partial update. Run the normal installer to repair the installation."
    exit 1
  fi

  stage_files
  backup_current_install
  ensure_upgrade_env_defaults
  install_staged_files

  echo "[INFO] Refreshing Python dependencies..."
  if ! "$APP_DIR/.venv/bin/pip" install --no-cache-dir -r "$APP_DIR/requirements.txt"; then
    restore_backup
    exit 1
  fi

  systemctl daemon-reload
  if ! systemctl restart marzban-watcher || ! verify_service; then
    echo "[ERROR] Updated service failed health verification."
    restore_backup
    echo "[ERROR] Previous installation restored."
    exit 1
  fi

  if [[ ! -f "$APP_LOG" ]]; then
    echo "[ERROR] Updated service did not create bounded application log: $APP_LOG"
    restore_backup
    echo "[ERROR] Previous installation restored."
    exit 1
  fi

  cleanup_legacy_logs
  echo
  echo "[OK] Marzban Watcher updated successfully."
  echo "[OK] Existing panel credentials and watcher settings were preserved."
  echo "[OK] Operational log is now bounded by LOG_MAX_MB and LOG_BACKUPS."
  echo "[OK] Hourly history is bounded by HISTORY_MAX_MB."
}

main() {
  require_root
  banner
  if [[ $UPDATE -eq 1 ]]; then
    upgrade_install
  else
    fresh_install
  fi

  echo "[OK] Command: marzban-watcher"
  echo "[OK] Old compatibility command: marzwatch"
  echo "[OK] Service: systemctl status marzban-watcher --no-pager -l"
  echo "[OK] Application log: $APP_LOG"
  echo "[OK] Install log: $LOG_FILE"
}

main "$@"
