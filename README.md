# Marzban Watcher

Live suspicious-usage watcher for Marzban with interactive install, safe in-place updates, bounded operational logs, live reports, hourly suspicious-history storage, and a simple control menu.

## What it does

- Connects to Marzban core and node logs through the official API and WebSocket endpoints.
- Builds a live suspicious-user report.
- Saves the latest report to `/var/lib/marzban-watcher/latest_report.txt`.
- Archives suspicious hourly snapshots in `/var/lib/marzban-watcher/hourly_suspicious.jsonl`.
- Runs as a `systemd` service.
- Uses bounded rotating operational logs so a reconnect loop cannot fill the server disk.
- Supports non-interactive in-place updates that preserve the existing panel configuration.

## Install

Use the panel base URL without `/hpanel` or another UI path.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ach1992/marzban-watcher/main/install.sh)
```

The installer creates:

```text
/opt/marzban-watcher/
/etc/marzban-watcher.env
/usr/local/bin/marzban-watcher
/usr/local/bin/marzwatch
/var/lib/marzban-watcher/latest_report.txt
/var/lib/marzban-watcher/hourly_suspicious.jsonl
/var/log/marzban-watcher.log
/var/log/marzban-watcher-install.log
```

## Update an existing installation

For installations that already have `/etc/marzban-watcher.env`, update without re-entering credentials or watcher settings:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ach1992/marzban-watcher/main/install.sh) --update
```

After this version is installed, future updates can also use:

```bash
marzban-watcher update
```

The update path:

1. downloads/stages all replacement files;
2. validates Python and shell syntax before replacing the installed files;
3. preserves the existing `/etc/marzban-watcher.env` values and only adds missing safe defaults;
4. restarts and verifies the new service;
5. rolls the installed files back if the updated service fails verification;
6. only after a successful restart, removes obsolete unbounded `marzban-watcher.stdout.log` and `marzban-watcher.stderr.log` files.

This means old installations that accumulated very large stdout/stderr logs reclaim that disk space automatically during a successful update.

## Bounded storage defaults

Operational logging is handled by Python's rotating file handler rather than `systemd` append-only stdout/stderr files.

Default values in `/etc/marzban-watcher.env`:

```text
LOG_MAX_MB=64
LOG_BACKUPS=3
HISTORY_MAX_MB=512
RECONNECT_MAX_DELAY=60
LOG_REPEAT_SECONDS=300
```

With the defaults, the operational application log uses at most approximately four 64 MiB files (current log plus three backups), or about 256 MiB total. Old rotated files are removed automatically.

The hourly suspicious JSONL history is also capped. When it exceeds `HISTORY_MAX_MB`, the oldest complete JSONL records are discarded and the newest records are retained. The cap is enforced at startup and after hourly writes, so old oversized installations self-correct after upgrade.

Repeated WebSocket failures use exponential reconnect backoff up to `RECONNECT_MAX_DELAY`, and repeated equivalent disconnect messages are rate-limited by `LOG_REPEAT_SECONDS`.

## Commands

```bash
marzban-watcher
marzban-watcher live
marzban-watcher latest
marzban-watcher hourly
marzban-watcher logs
marzban-watcher status
marzban-watcher reconfigure
marzban-watcher update
marzban-watcher start
marzban-watcher stop
marzban-watcher restart
marzban-watcher uninstall
```

The old compatibility command remains available:

```bash
marzwatch
```

## Service and diagnostics

```bash
systemctl status marzban-watcher --no-pager -l
marzban-watcher logs
journalctl -u marzban-watcher -n 100 --no-pager
```

Normal operational messages are written to the bounded `/var/log/marzban-watcher.log`. `systemd` stdout is disabled and stderr is reserved as a journal fallback for process-level failures.

## Offline install

Copy these files into one directory:

- `marzban_watch.py`
- `marzban-watcher`
- `marzban-watcher.service`
- `install.sh`
- `uninstall.sh`
- `requirements.txt`

Then run:

```bash
bash install.sh --offline
```

An existing installation can be updated from the same local files with:

```bash
bash install.sh --offline --update
```

## Notes

- Login uses the Marzban token request format with `grant_type=password`.
- If a node WebSocket returns `403 Forbidden`, the watcher continues operating for reachable sources. Reconnect attempts are bounded with backoff and log suppression.
- Live output is sorted by unique IP count, then connection count, then username.
- `LIVE_TOP` controls how many rows are stored in the current live report. Default: `50`.
- The data directory and generated report/history files use restrictive permissions because reports can contain usernames and source IP addresses.
