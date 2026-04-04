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
import os
import signal
import ssl
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import requests
import websocket


APP_NAME = "Marzban Watcher"
APP_LINE = "=" * 120


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


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def append_jsonl(path: str, obj: dict) -> None:
    ensure_dir(str(Path(path).parent))
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + '\n')


def write_text(path: str, text: str) -> None:
    ensure_dir(str(Path(path).parent))
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


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


class RollingStats:
    def __init__(self, max_window_seconds: int):
        self.max_window = max_window_seconds
        self.events = deque()  # (arrival_ts, username, ip, source_name)
        self.conn_count = Counter()
        self.user_ip_counter = defaultdict(Counter)
        self.user_source_counter = defaultdict(Counter)
        self.lock = threading.Lock()

    def _cleanup(self, now_ts: float):
        cutoff = now_ts - self.max_window
        while self.events and self.events[0][0] < cutoff:
            _, username, ip, source_name = self.events.popleft()
            self.conn_count[username] -= 1
            if self.conn_count[username] <= 0:
                self.conn_count.pop(username, None)
            self.user_ip_counter[username][ip] -= 1
            if self.user_ip_counter[username][ip] <= 0:
                self.user_ip_counter[username].pop(ip, None)
            if not self.user_ip_counter[username]:
                self.user_ip_counter.pop(username, None)
            self.user_source_counter[username][source_name] -= 1
            if self.user_source_counter[username][source_name] <= 0:
                self.user_source_counter[username].pop(source_name, None)
            if not self.user_source_counter[username]:
                self.user_source_counter.pop(username, None)

    def add(self, username: str, ip: str, source_name: str):
        now_ts = time.time()
        with self.lock:
            self.events.append((now_ts, username, ip, source_name))
            self.conn_count[username] += 1
            self.user_ip_counter[username][ip] += 1
            self.user_source_counter[username][source_name] += 1
            self._cleanup(now_ts)

    def snapshot(self, window_seconds: int):
        now_ts = time.time()
        cutoff = now_ts - window_seconds
        result_conn = Counter()
        result_ip = defaultdict(Counter)
        result_source = defaultdict(Counter)
        with self.lock:
            self._cleanup(now_ts)
            for ts, username, ip, source_name in self.events:
                if ts < cutoff:
                    continue
                result_conn[username] += 1
                result_ip[username][ip] += 1
                result_source[username][source_name] += 1
        rows = []
        for username, conns in result_conn.items():
            rows.append({
                'username': username,
                'conns': conns,
                'uniq_ips': len(result_ip[username]),
                'ips': dict(result_ip[username]),
                'sources': dict(result_source[username]),
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


def worker(label, url, stats: RollingStats, insecure: bool, reconnect_delay: int, stop_evt: threading.Event):
    sslopt = None
    if url.startswith('wss://'):
        sslopt = {'cert_reqs': ssl.CERT_NONE} if insecure else None
    while not stop_evt.is_set():
        ws = None
        try:
            ws = websocket.create_connection(url, timeout=20, sslopt=sslopt)
            print(f'[INFO] connected to {label}', file=sys.stderr, flush=True)
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
            print(f'[WARN] {label} disconnected: {exc}', file=sys.stderr, flush=True)
            time.sleep(reconnect_delay)
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


def main():
    parser = argparse.ArgumentParser(description='Live Marzban watcher using official Marzban APIs and websockets.')
    parser.add_argument('--base-url', required=True, help='Example: https://panel.example.com:8443')
    parser.add_argument('--api-prefix', default='/api')
    parser.add_argument('--username')
    parser.add_argument('--password')
    parser.add_argument('--token')
    parser.add_argument('--insecure', action='store_true')
    parser.add_argument('--source-interval', type=float, default=1.0, help='WebSocket interval aggregation seconds (<=10)')
    parser.add_argument('--refresh', type=int, default=10, help='Refresh live report every N seconds')
    parser.add_argument('--live-window', type=int, default=300)
    parser.add_argument('--live-ip-limit', type=int, default=3)
    parser.add_argument('--live-conn-limit', type=int, default=40)
    parser.add_argument('--live-top', type=int, default=50)
    parser.add_argument('--show-all', action='store_true')
    parser.add_argument('--hourly-window', type=int, default=3600)
    parser.add_argument('--hourly-ip-limit', type=int, default=4)
    parser.add_argument('--hourly-conn-limit', type=int, default=250)
    parser.add_argument('--hourly-file', default='/var/lib/marzban-watcher/hourly_suspicious.jsonl')
    parser.add_argument('--latest-file', default='/var/lib/marzban-watcher/latest_report.txt')
    parser.add_argument('--reconnect-delay', type=int, default=3)
    args = parser.parse_args()

    if not args.token and (not args.username or not args.password):
        parser.error('Provide either --token or both --username and --password')
    if args.source_interval <= 0 or args.source_interval > 10:
        parser.error('--source-interval must be >0 and <=10')

    session = requests.Session()
    session.verify = not args.insecure
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    token = args.token or login(session, args.base_url, args.api_prefix, args.username, args.password)
    nodes = get_nodes(session, args.base_url, args.api_prefix, token)

    stats = RollingStats(max(args.live_window, args.hourly_window))
    stop_evt = threading.Event()
    install_signal_handlers(stop_evt)

    targets = []
    core_ws = ws_url(args.base_url, args.api_prefix, 'core/logs', token, args.source_interval)
    targets.append(('Master', core_ws))
    for node in nodes:
        nid = node['id']
        nname = node.get('name', f'node-{nid}')
        node_ws = ws_url(args.base_url, args.api_prefix, f'node/{nid}/logs', token, args.source_interval)
        targets.append((nname, node_ws))

    for label, url in targets:
        t = threading.Thread(target=worker, args=(label, url, stats, args.insecure, args.reconnect_delay, stop_evt), daemon=True)
        t.start()

    last_live = 0.0
    last_hour = int(time.time() // 3600)

    while not stop_evt.is_set():
        now = time.time()
        if now - last_live >= args.refresh:
            live_rows = stats.snapshot(args.live_window)
            report = format_rows(live_rows, args.live_ip_limit, args.live_conn_limit, args.live_top, args.show_all)
            write_text(args.latest_file, report)
            print(report, end='')
            last_live = now

        current_hour = int(now // 3600)
        if current_hour != last_hour:
            hour_rows = stats.snapshot(args.hourly_window)
            records = hourly_records(hour_rows, args.hourly_ip_limit, args.hourly_conn_limit)
            for record in records:
                append_jsonl(args.hourly_file, record)
            if records:
                print(f'[INFO] wrote {len(records)} hourly suspicious records to {args.hourly_file}', file=sys.stderr, flush=True)
            last_hour = current_hour

        time.sleep(1)


if __name__ == '__main__':
    main()
