# Marzban Watcher

Live suspicious usage watcher for Marzban with interactive install, online one-liner setup, offline install, simple menu, reconfigure support, logs, and uninstall.

Repository:
- Name: **Marzban Watcher**
- URL: `https://github.com/ach1992/marzban-watcher`

## What it does

- Connects to Marzban core logs and node logs through official API and websocket endpoints.
- Builds a live suspicious-user report.
- Saves the latest report to disk.
- Archives suspicious hourly snapshots as JSONL.
- Runs as a systemd service.
- Gives you a simple control menu with the command:

```bash
marzban-watcher
```

It also keeps old command compatibility:

```bash
marzwatch
```

---

## Important note about Base URL

Use your panel base URL **without** `/hpanel`.

Correct:

```bash
https://panel.example.com:8443
```

Wrong:

```bash
https://panel.example.com:8443/hpanel/
```

---

## Remove old manual installation first

If you previously installed the older manual version, remove it first:

```bash
systemctl stop marzban-watch 2>/dev/null || true
systemctl disable marzban-watch 2>/dev/null || true
rm -f /etc/systemd/system/marzban-watch.service
rm -f /usr/local/bin/marzwatch
rm -rf /opt/marzban-watch
rm -f /etc/marzban-watch.env
rm -rf /var/lib/marzban-watch
rm -f /var/log/marzban-watch.stdout.log /var/log/marzban-watch.stderr.log
systemctl daemon-reload
systemctl reset-failed
```

Or use the new uninstaller after the new version is installed:

```bash
marzban-watcher uninstall
```

---

## Online install (one-liner)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ach1992/marzban-watcher/main/install.sh)
```

The installer will:
- install dependencies
- ask for your Marzban panel info
- write the env config
- create the virtual environment
- install Python packages
- install and start the service
- write install logs to:

```bash
/var/log/marzban-watcher-install.log
```

---

## Offline install

Download or copy these files into a folder like:

```bash
/root/marzban-watcher/
```

Required files:

- `marzban_watch.py`
- `marzban-watcher`
- `marzban-watcher.service`
- `install.sh`
- `uninstall.sh`
- `requirements.txt`

Then run:

```bash
cd /root/marzban-watcher
bash install.sh --offline
```

---

## Start the menu

```bash
marzban-watcher
```

Menu actions:
- Live
- Latest
- Hourly
- Logs
- Status
- Reconfigure
- Start
- Stop
- Restart
- Uninstall
- Exit

---

## Direct commands

```bash
marzban-watcher live
marzban-watcher latest
marzban-watcher hourly
marzban-watcher logs
marzban-watcher status
marzban-watcher reconfigure
marzban-watcher start
marzban-watcher stop
marzban-watcher restart
marzban-watcher uninstall
```

Old compatibility command:

```bash
marzwatch live
marzwatch latest
marzwatch hourly
marzwatch logs
```

---

## Service management

```bash
systemctl status marzban-watcher --no-pager -l
journalctl -u marzban-watcher -n 100 --no-pager
```

---

## Files and paths

```bash
/opt/marzban-watcher/
/etc/marzban-watcher.env
/usr/local/bin/marzban-watcher
/usr/local/bin/marzwatch
/var/lib/marzban-watcher/latest_report.txt
/var/lib/marzban-watcher/hourly_suspicious.jsonl
/var/log/marzban-watcher.stdout.log
/var/log/marzban-watcher.stderr.log
/var/log/marzban-watcher-install.log
```

---

## Notes

- Login uses the correct Marzban token request format with `grant_type=password`.
- If some nodes show websocket `403 Forbidden`, the watcher still works, but those nodes likely need proxy or websocket access fixes on the panel side.
- If you change the panel password, run:

```bash
marzban-watcher reconfigure
```

---


## Notes

- `BASE_URL` must be entered **without** `/hpanel`.
- The installer and `reconfigure` now sanitize credentials to a single line to avoid broken `ADMIN_PASS` values in the env file.
- Live output is sorted by **unique IP count descending**, then **connection count descending**, then username.
- `LIVE_TOP` controls how many rows are shown in the live report. Default: `50`.
