#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="marzban-watcher"
OLD_SERVICE="marzban-watch"

echo "This will remove Marzban Watcher from this server."
read -r -p "Continue? [y/N]: " ans
case "$ans" in
  y|Y|yes|YES) ;;
  *) echo "Canceled."; exit 0 ;;
esac

systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
systemctl stop "$OLD_SERVICE" 2>/dev/null || true
systemctl disable "$OLD_SERVICE" 2>/dev/null || true

rm -f /etc/systemd/system/marzban-watcher.service
rm -f /etc/systemd/system/marzban-watch.service
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

rm -f /usr/local/bin/marzban-watcher
rm -f /usr/local/bin/marzwatch
rm -rf /opt/marzban-watcher
rm -rf /opt/marzban-watch
rm -f /etc/marzban-watcher.env
rm -f /etc/marzban-watch.env
rm -rf /var/lib/marzban-watcher
rm -rf /var/lib/marzban-watch
rm -f /var/log/marzban-watcher.stdout.log
rm -f /var/log/marzban-watcher.stderr.log
rm -f /var/log/marzban-watch.stdout.log
rm -f /var/log/marzban-watch.stderr.log

echo "[OK] Marzban Watcher removed."
