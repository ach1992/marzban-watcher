#!/usr/bin/env python3
"""
============================================================
 Marzban Watcher
 Live suspicious usage watcher for Marzban nodes and core logs
 GitHub: https://github.com/ach1992/marzban-watcher
============================================================
"""

import argparse
import json
import logging
import os
import re
import signal
import ssl
import threading
import time
import traceback
import urllib.parse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests
import websocket


APP_NAME = "Marzban Watcher"
APP_LINE = "=" * 120
DEFAULT_LOG_FILE = "/var/log/marzban-watcher.log"
DEFAULT_LOG_MAX_MB = 64
DEFAULT_LOG_BACKUPS = 3
DEFAULT_HISTORY_MAX_MB = 512
DEFAULT_RECONNECT_MAX_DELAY = 60
DEFAULT_LOG_REPEAT_SECONDS = 300
DEFAULT_STATS_MAX_BUCKETS = 300


def join_path(*parts: str) -> str:
    items = []
    for part in parts:
        if not part:
            continue
        items.extend([p for p in str(part).split('/') if p])
    return '/' + '/'.join(items)


def api_url(base_url: str, api_prefix: str, suffix: str) -> str:
    p = urllib.parse.urlparse(base_url.rstrip('/'))
    path = join_path(p.path, api_prefix, suffix)
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, '', '', ''))


def ws_url(base_url: str, api_prefix: str, suffix: str, token: str, interval: float) -> str:
    p = urllib.parse.urlparse(base_url.rstrip('/'))
    scheme = 'wss' if p.scheme == 'https' else 'ws'
    path = join_path(p.path, api_prefix, suffix)
    query = urllib.parse.urlencode({'token': token, 'interval': str(interval)})
    return urllib.parse.urlunparse((scheme, p.netloc, path, '', query, ''))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def ensure_dir(path: str, mode=None) -> None:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        try:
            os.chmod(directory, mode)
        except PermissionError:
            pass


def secure_file(path: str, mode: int = 0o600) -> None:
    try:
        if os.path.exists(path):
            os.chmod(path, mode)
    except PermissionError:
        pass


def append_jsonl(path: str, obj: dict) -> None:
    ensure_dir(str(Path(path).parent), 0o700)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + '\n')
    secure_file(path)


def write_text(path: str, text: str) -> None:
    ensure_dir(str(Path(path).parent), 0o700)
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    secure_file(tmp)
    os.replace(tmp, path)
    secure_file(path)


def trim_jsonl_to_max_bytes(path: str, max_bytes: int) -> bool:
    """Keep the newest complete JSONL records within max_bytes."""
    if max_bytes <= 0 or not os.path.isfile(path):
        return False

    size = os.path.getsize(path)
    secure_file(path)
    if size <= max_bytes:
        return False

    start = max(0, size - max_bytes)
    with open(path, 'r+b') as handle:
        handle.seek(start)
        if start > 0:
            handle.readline()
        read_pos = handle.tell()
        write_pos = 0

        while True:
            handle.seek(read_pos)
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            handle.seek(write_pos)
            handle.write(chunk)
            read_pos += len(chunk)
            write_pos += len(chunk)

        handle.truncate(write_pos)
        handle.flush()
        os.fsync(handle.fileno())

    secure_file(path)
    return True


def sanitize_log_message(value: object) -> str:
    text = str(value)
    text = re.sub(r'(?i)(token=)[^&\s]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(authorization:\s*bearer\s+)[^\s]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(access_token["\'=:\s]+)[^\s,}"\']+', r'\1[REDACTED]', text)
    return text


def configure_logger(path: str, max_mb: int, backups: int) -> logging.Logger:
    ensure_dir(str(Path(path).parent))
    logger = logging.getLogger('marzban-watcher')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = RotatingFileHandler(
        path,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups,
        encoding='utf-8',
    )
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    secure_file(path, 0o640)
    return logger


def parse_log_line(line: str):
    if ' accepted ' not in line or ' email:' not in line:
        return None
    try:
        after_from = line.split(' from ', 1)[1]
        src = after_from.split(' accepted ', 1)[0].strip()
        if src.startswith('tcp:') or src.startswith('udp:'):
            src = src[4:]
        ip = src.rsplit(':', 1)[0].strip('[]')
        username = line.rsplit(' email:', 1)[1].strip().split()[0]
        if not ip or not username:
            return None
        return username, ip
    except Exception:
        return None


class RollingWindowState:
    def __init__(self, window_seconds: int, max_buckets: int):
        self.window_seconds = window_seconds
        self.bucket_seconds = max(1.0, window_seconds / max_buckets)
        self.buckets = deque()
        self.current_bucket_id = None
        self.current_bucket = None
        self.conn_count = Counter()
        self.user_ip_counter = defaultdict(Counter)
        self.user_source_counter = defaultdict(Counter)


class RollingStats:
    """Rolling counters with adaptive time buckets.

    Each configured window keeps at most roughly ``max_buckets`` time buckets.
    A bucket aggregates connection counts per user, IP, and source, so memory
    scales with distinct identities in a bounded number of time slices rather
    than with every raw connection event. Window boundaries are quantized by at
    most one bucket (default: about 0.33% of each window).
    """

    def __init__(self, window_seconds, max_buckets: int = DEFAULT_STATS_MAX_BUCKETS):
        if isinstance(window_seconds, int):
            windows = [window_seconds]
        else:
            windows = list(window_seconds)
        windows = sorted(set(int(window) for window in windows))
        if not windows or any(window <= 0 for window in windows):
            raise ValueError('rolling windows must be positive integers')
        if max_buckets <= 0:
            raise ValueError('max_buckets must be greater than zero')

        self.max_buckets = int(max_buckets)
        self.states = {
            window: RollingWindowState(window, self.max_buckets)
            for window in windows
        }
        self.lock = threading.Lock()

    @staticmethod
    def _decrement(counter: Counter, key, amount: int) -> None:
        remaining = counter.get(key, 0) - amount
        if remaining > 0:
            counter[key] = remaining
        else:
            counter.pop(key, None)

    def _remove_bucket(self, state: RollingWindowState, bucket) -> None:
        _, conn_count, user_ip_counter, user_source_counter = bucket

        for username, amount in conn_count.items():
            self._decrement(state.conn_count, username, amount)

        for username, ip_counts in user_ip_counter.items():
            state_ip_counts = state.user_ip_counter.get(username)
            if state_ip_counts is None:
                continue
            for ip, amount in ip_counts.items():
                self._decrement(state_ip_counts, ip, amount)
            if not state_ip_counts:
                state.user_ip_counter.pop(username, None)

        for username, source_counts in user_source_counter.items():
            state_source_counts = state.user_source_counter.get(username)
            if state_source_counts is None:
                continue
            for source_name, amount in source_counts.items():
                self._decrement(state_source_counts, source_name, amount)
            if not state_source_counts:
                state.user_source_counter.pop(username, None)

    def _cleanup_state(self, state: RollingWindowState, now_ts: float) -> None:
        cutoff = now_ts - state.window_seconds
        while state.buckets and state.buckets[0][0] + state.bucket_seconds <= cutoff:
            bucket = state.buckets.popleft()
            self._remove_bucket(state, bucket)

    def _bucket_for(self, state: RollingWindowState, now_ts: float):
        bucket_id = int(now_ts // state.bucket_seconds)
        if state.current_bucket_id == bucket_id and state.current_bucket is not None:
            return state.current_bucket

        bucket_start = bucket_id * state.bucket_seconds
        bucket = [bucket_start, Counter(), defaultdict(Counter), defaultdict(Counter)]
        state.current_bucket_id = bucket_id
        state.current_bucket = bucket
        state.buckets.append(bucket)
        self._cleanup_state(state, now_ts)
        return bucket

    def add(self, username: str, ip: str, source_name: str, now_ts: float = None):
        if now_ts is None:
            now_ts = time.monotonic()
        with self.lock:
            for state in self.states.values():
                bucket = self._bucket_for(state, now_ts)
                _, bucket_conn, bucket_ips, bucket_sources = bucket

                bucket_conn[username] += 1
                bucket_ips[username][ip] += 1
                bucket_sources[username][source_name] += 1

                state.conn_count[username] += 1
                state.user_ip_counter[username][ip] += 1
                state.user_source_counter[username][source_name] += 1

    def snapshot(self, window_seconds: int, now_ts: float = None):
        if now_ts is None:
            now_ts = time.monotonic()
        try:
            state = self.states[int(window_seconds)]
        except KeyError as exc:
            raise ValueError(f'unconfigured rolling window: {window_seconds}') from exc

        with self.lock:
            self._cleanup_state(state, now_ts)
            rows = []
            for username, conns in state.conn_count.items():
                ips = state.user_ip_counter.get(username, {})
                sources = state.user_source_counter.get(username, {})
                rows.append({
                    'username': username,
                    'conns': conns,
                    'uniq_ips': len(ips),
                    'ips': dict(ips),
                    'sources': dict(sources),
                })

        rows.sort(key=lambda r: (-r['uniq_ips'], -r['conns'], r['username']))
        return rows


def login(session: requests.Session, base_url: str, api_prefix: str, username: str, password: str) -> str:
    url = api_url(base_url, api_prefix, 'admin/token')
    data = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': '',
        'client_id': '',
        'client_secret': '',
    }
    resp = session.post(
        url,
        data=data,
        headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=20,
    )
    resp.raise_for_status()
    token = resp.json().get('access_token')
    if not token:
        raise RuntimeError(f'No access_token returned from {url}')
    return token


def get_nodes(session: requests.Session, base_url: str, api_prefix: str, token: str):
    url = api_url(base_url, api_prefix, 'nodes')
    resp = session.get(url, headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'}, timeout=20)
    resp.raise_for_status()
    payload = resp.json()
    if isinstance(payload, dict) and 'nodes' in payload:
        payload = payload['nodes']
    if not isinstance(payload, list):
        raise RuntimeError(f'Unexpected /nodes response: {payload}')
    return payload


def worker(
    label,
    url,
    stats: RollingStats,
    insecure: bool,
    reconnect_delay: int,
    reconnect_max_delay: int,
    log_repeat_seconds: int,
    stop_evt: threading.Event,
    logger: logging.Logger,
):
    sslopt = None
    if url.startswith('wss://'):
        sslopt = {'cert_reqs': ssl.CERT_NONE} if insecure else None

    base_delay = max(1, reconnect_delay)
    retry_delay = base_delay
    consecutive_failures = 0
    suppressed_failures = 0
    last_warning = 0.0
    ever_connected = False

    while not stop_evt.is_set():
        ws = None
        try:
            ws = websocket.create_connection(url, timeout=20, sslopt=sslopt)
            if consecutive_failures:
                logger.info('%s reconnected after %d failed attempt(s)', label, consecutive_failures)
            elif not ever_connected:
                logger.info('%s connected', label)
            ever_connected = True
            consecutive_failures = 0
            suppressed_failures = 0
            retry_delay = base_delay

            while not stop_evt.is_set():
                message = ws.recv()
                if message is None:
                    continue
                for line in str(message).splitlines():
                    parsed = parse_log_line(line.strip())
                    if not parsed:
                        continue
                    username, ip = parsed
                    stats.add(username, ip, label)
        except KeyboardInterrupt:
            return
        except Exception as exc:
            consecutive_failures += 1
            now = time.monotonic()
            should_log = consecutive_failures == 1 or now - last_warning >= log_repeat_seconds
            if should_log:
                suffix = ''
                if suppressed_failures:
                    suffix = f' ({suppressed_failures} similar failure(s) suppressed)'
                logger.warning(
                    '%s disconnected: %s; retrying in %ss%s',
                    label,
                    sanitize_log_message(exc),
                    retry_delay,
                    suffix,
                )
                last_warning = now
                suppressed_failures = 0
            else:
                suppressed_failures += 1

            if stop_evt.wait(retry_delay):
                return
            retry_delay = min(reconnect_max_delay, max(base_delay, retry_delay * 2))
        finally:
            try:
                if ws:
                    ws.close()
            except Exception:
                pass


def row_flag(row, ip_limit: int, conn_limit: int) -> bool:
    return row['uniq_ips'] >= ip_limit or row['conns'] >= conn_limit


def format_rows(rows, ip_limit: int, conn_limit: int, top_n: int, show_all: bool) -> str:
    filtered = []
    for row in rows:
        flagged = row_flag(row, ip_limit, conn_limit)
        if show_all or flagged:
            top_ips = sorted(row['ips'].items(), key=lambda x: (-x[1], x[0]))[:5]
            top_sources = sorted(row['sources'].items(), key=lambda x: (-x[1], x[0]))
            filtered.append({
                'flag': 'CHECK' if flagged else '',
                'uniq_ips': row['uniq_ips'],
                'conns': row['conns'],
                'username': row['username'],
                'sources': ', '.join(f'{k}({v})' for k, v in top_sources),
                'ips': ', '.join(f'{k}({v})' for k, v in top_ips),
            })
    filtered = filtered[:top_n]
    lines = []
    lines.append(APP_LINE)
    lines.append(f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] live view')
    lines.append('-' * 120)
    lines.append(f"{'FLAG':<8} {'UNIQ_IP':<8} {'CONN':<8} {'USERNAME':<42} {'SOURCES':<40} TOP_IPS")
    lines.append('-' * 120)
    if not filtered:
        lines.append('No suspicious users in current live window.')
    else:
        for row in filtered:
            lines.append(
                f"{row['flag']:<8} {row['uniq_ips']:<8} {row['conns']:<8} {row['username']:<42} {row['sources']:<40} {row['ips']}"
            )
    return '\n'.join(lines) + '\n'


def hourly_records(rows, ip_limit: int, conn_limit: int):
    out = []
    stamp = iso_now()
    for row in rows:
        if not row_flag(row, ip_limit, conn_limit):
            continue
        out.append({
            'timestamp': stamp,
            'username': row['username'],
            'uniq_ips': row['uniq_ips'],
            'connections': row['conns'],
            'sources': row['sources'],
            'top_ips': dict(sorted(row['ips'].items(), key=lambda x: (-x[1], x[0]))[:10]),
        })
    return out


def install_signal_handlers(stop_evt: threading.Event):
    def _handler(signum, frame):
        stop_evt.set()
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be greater than zero')
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be greater than zero')
    return parsed


def env_default(name: str, default=None):
    value = os.environ.get(name)
    if value is None or value == '':
        return default
    return value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or value == '':
        return default
    normalized = value.strip().lower()
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Live Marzban watcher using official Marzban APIs and websockets.')
    parser.add_argument('--base-url', default=env_default('BASE_URL'), help='Example: https://panel.example.com:8443')
    parser.add_argument('--api-prefix', default=env_default('API_PREFIX', '/api'))
    parser.add_argument('--username', default=env_default('ADMIN_USER'))
    parser.add_argument('--password', default=env_default('ADMIN_PASS'))
    parser.add_argument('--token', default=env_default('MARZBAN_TOKEN'))
    parser.add_argument('--insecure', action='store_true', default=env_bool('INSECURE', False))
    parser.add_argument('--source-interval', type=positive_float, default=env_default('SOURCE_INTERVAL', '1.0'), help='WebSocket interval aggregation seconds (<=10)')
    parser.add_argument('--refresh', type=positive_int, default=env_default('REFRESH', '10'), help='Refresh live report every N seconds')
    parser.add_argument('--live-window', type=positive_int, default=env_default('LIVE_WINDOW', '300'))
    parser.add_argument('--live-ip-limit', type=positive_int, default=env_default('LIVE_IP_LIMIT', '3'))
    parser.add_argument('--live-conn-limit', type=positive_int, default=env_default('LIVE_CONN_LIMIT', '40'))
    parser.add_argument('--live-top', type=positive_int, default=env_default('LIVE_TOP', '50'))
    parser.add_argument('--show-all', action='store_true', default=env_bool('SHOW_ALL', False))
    parser.add_argument('--hourly-window', type=positive_int, default=env_default('HOURLY_WINDOW', '3600'))
    parser.add_argument('--hourly-ip-limit', type=positive_int, default=env_default('HOURLY_IP_LIMIT', '4'))
    parser.add_argument('--hourly-conn-limit', type=positive_int, default=env_default('HOURLY_CONN_LIMIT', '250'))
    parser.add_argument('--hourly-file', default=env_default('HOURLY_FILE', '/var/lib/marzban-watcher/hourly_suspicious.jsonl'))
    parser.add_argument('--latest-file', default=env_default('LATEST_FILE', '/var/lib/marzban-watcher/latest_report.txt'))
    parser.add_argument('--reconnect-delay', type=positive_int, default=env_default('RECONNECT_DELAY', '3'))
    parser.add_argument('--reconnect-max-delay', type=positive_int, default=env_default('RECONNECT_MAX_DELAY', str(DEFAULT_RECONNECT_MAX_DELAY)))
    parser.add_argument('--log-repeat-seconds', type=positive_int, default=env_default('LOG_REPEAT_SECONDS', str(DEFAULT_LOG_REPEAT_SECONDS)))
    parser.add_argument('--log-file', default=env_default('LOG_FILE', DEFAULT_LOG_FILE))
    parser.add_argument('--log-max-mb', type=positive_int, default=env_default('LOG_MAX_MB', str(DEFAULT_LOG_MAX_MB)))
    parser.add_argument('--log-backups', type=positive_int, default=env_default('LOG_BACKUPS', str(DEFAULT_LOG_BACKUPS)))
    parser.add_argument('--history-max-mb', type=positive_int, default=env_default('HISTORY_MAX_MB', str(DEFAULT_HISTORY_MAX_MB)))
    parser.add_argument('--stats-max-buckets', type=positive_int, default=env_default('STATS_MAX_BUCKETS', str(DEFAULT_STATS_MAX_BUCKETS)))
    return parser


def parse_args(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.base_url:
        parser.error('Provide --base-url or BASE_URL')
    if not args.token and (not args.username or not args.password):
        parser.error('Provide either --token/MARZBAN_TOKEN or username and password via arguments/environment')
    if args.source_interval > 10:
        parser.error('--source-interval must be <=10')
    if args.reconnect_max_delay < args.reconnect_delay:
        parser.error('--reconnect-max-delay must be >= --reconnect-delay')
    return args


def main():
    args = parse_args()

    logger = configure_logger(args.log_file, args.log_max_mb, args.log_backups)
    logger.info('%s starting', APP_NAME)

    try:
        ensure_dir(str(Path(args.hourly_file).parent), 0o700)
        secure_file(args.hourly_file)
        secure_file(args.latest_file)
        if trim_jsonl_to_max_bytes(args.hourly_file, args.history_max_mb * 1024 * 1024):
            logger.info('trimmed hourly history to configured %d MiB cap', args.history_max_mb)

        session = requests.Session()
        session.verify = not args.insecure
        if args.insecure:
            requests.packages.urllib3.disable_warnings()

        stats = RollingStats(
            [args.live_window, args.hourly_window],
            max_buckets=args.stats_max_buckets,
        )
        stop_evt = threading.Event()
        install_signal_handlers(stop_evt)

        targets = []
        startup_delay = max(1, args.reconnect_delay)
        startup_failures = 0
        startup_suppressed = 0
        startup_last_warning = 0.0
        while not stop_evt.is_set():
            try:
                token = args.token or login(session, args.base_url, args.api_prefix, args.username, args.password)
                nodes = get_nodes(session, args.base_url, args.api_prefix, token)
                core_ws = ws_url(args.base_url, args.api_prefix, 'core/logs', token, args.source_interval)
                targets = [('Master', core_ws)]
                for node in nodes:
                    nid = node['id']
                    nname = node.get('name', f'node-{nid}')
                    node_ws = ws_url(args.base_url, args.api_prefix, f'node/{nid}/logs', token, args.source_interval)
                    targets.append((nname, node_ws))
                if startup_failures:
                    logger.info('Marzban API connection recovered after %d failed attempt(s)', startup_failures)
                break
            except Exception as exc:
                startup_failures += 1
                now_mono = time.monotonic()
                if startup_failures == 1 or now_mono - startup_last_warning >= args.log_repeat_seconds:
                    suffix = ''
                    if startup_suppressed:
                        suffix = f' ({startup_suppressed} similar failure(s) suppressed)'
                    logger.warning(
                        'Marzban API unavailable: %s; retrying in %ss%s',
                        sanitize_log_message(exc),
                        startup_delay,
                        suffix,
                    )
                    startup_last_warning = now_mono
                    startup_suppressed = 0
                else:
                    startup_suppressed += 1
                if stop_evt.wait(startup_delay):
                    break
                startup_delay = min(args.reconnect_max_delay, max(args.reconnect_delay, startup_delay * 2))

        if stop_evt.is_set():
            logger.info('%s stopping before API connection was established', APP_NAME)
            return

        logger.info('watching %d websocket source(s)', len(targets))
        for label, url in targets:
            t = threading.Thread(
                target=worker,
                args=(
                    label,
                    url,
                    stats,
                    args.insecure,
                    args.reconnect_delay,
                    args.reconnect_max_delay,
                    args.log_repeat_seconds,
                    stop_evt,
                    logger,
                ),
                daemon=True,
            )
            t.start()

        last_live = 0.0
        last_hour = int(time.time() // 3600)

        while not stop_evt.is_set():
            now = time.time()
            if now - last_live >= args.refresh:
                live_rows = stats.snapshot(args.live_window)
                report = format_rows(live_rows, args.live_ip_limit, args.live_conn_limit, args.live_top, args.show_all)
                write_text(args.latest_file, report)
                last_live = now

            current_hour = int(now // 3600)
            if current_hour != last_hour:
                hour_rows = stats.snapshot(args.hourly_window)
                records = hourly_records(hour_rows, args.hourly_ip_limit, args.hourly_conn_limit)
                for record in records:
                    append_jsonl(args.hourly_file, record)
                if records:
                    logger.info('wrote %d hourly suspicious record(s)', len(records))
                if trim_jsonl_to_max_bytes(args.hourly_file, args.history_max_mb * 1024 * 1024):
                    logger.info('trimmed hourly history to configured %d MiB cap', args.history_max_mb)
                last_hour = current_hour

            stop_evt.wait(1)

        logger.info('%s stopping', APP_NAME)
    except Exception as exc:
        detail = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        logger.error('fatal error:\n%s', sanitize_log_message(detail).rstrip())
        raise


if __name__ == '__main__':
    main()
