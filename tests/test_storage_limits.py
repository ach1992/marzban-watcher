import importlib.util
import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / 'marzban_watch.py'
spec = importlib.util.spec_from_file_location('marzban_watch', MODULE_PATH)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)


class StorageLimitTests(unittest.TestCase):
    def tearDown(self):
        logger = logging.getLogger('marzban-watcher')
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    def test_sanitize_log_message_redacts_tokens(self):
        text = 'wss://example.test/logs?token=secret-value&interval=1 Authorization: Bearer abc123'
        cleaned = watcher.sanitize_log_message(text)
        self.assertNotIn('secret-value', cleaned)
        self.assertNotIn('abc123', cleaned)
        self.assertIn('token=[REDACTED]', cleaned)

    def test_history_trim_keeps_recent_complete_jsonl_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.jsonl'
            rows = []
            with path.open('w', encoding='utf-8') as handle:
                for index in range(200):
                    row = {'index': index, 'payload': 'x' * 80}
                    rows.append(row)
                    handle.write(json.dumps(row) + '\n')

            original_size = path.stat().st_size
            self.assertGreater(original_size, 4096)
            changed = watcher.trim_jsonl_to_max_bytes(str(path), 4096)
            self.assertTrue(changed)
            self.assertLessEqual(path.stat().st_size, 4096)

            with path.open('r', encoding='utf-8') as handle:
                retained = [json.loads(line) for line in handle if line.strip()]
            self.assertTrue(retained)
            self.assertEqual(retained[-1]['index'], rows[-1]['index'])
            self.assertGreater(retained[0]['index'], 0)

    def test_history_trim_handles_overlapping_in_place_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.jsonl'
            with path.open('w', encoding='utf-8') as handle:
                for index in range(40000):
                    handle.write(json.dumps({'index': index, 'payload': 'z' * 140}) + '\n')

            self.assertGreater(path.stat().st_size, 5 * 1024 * 1024)
            changed = watcher.trim_jsonl_to_max_bytes(str(path), 2 * 1024 * 1024)
            self.assertTrue(changed)
            self.assertLessEqual(path.stat().st_size, 2 * 1024 * 1024)
            with path.open('r', encoding='utf-8') as handle:
                retained = [json.loads(line) for line in handle if line.strip()]
            self.assertTrue(retained)
            self.assertEqual(retained[-1]['index'], 39999)

    def test_rotating_logger_bounds_file_count_and_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / 'watcher.log'
            logger = watcher.configure_logger(str(log_path), max_mb=1, backups=2)
            payload = 'x' * 100_000
            for index in range(40):
                logger.info('%04d %s', index, payload)
            for handler in logger.handlers:
                handler.flush()

            files = sorted(Path(tmp).glob('watcher.log*'))
            self.assertLessEqual(len(files), 3)
            self.assertTrue(all(path.stat().st_size <= 1_100_000 for path in files))
            self.assertLessEqual(sum(path.stat().st_size for path in files), 3_200_000)


class RollingStatsTests(unittest.TestCase):
    def test_repeated_connections_are_aggregated_per_bucket(self):
        stats = watcher.RollingStats([10, 60], max_buckets=60)
        for _ in range(10000):
            stats.add('alice', '203.0.113.10', 'node-a', now_ts=100.25)

        live = stats.snapshot(10, now_ts=100.5)
        self.assertEqual(live[0]['conns'], 10000)
        self.assertEqual(live[0]['uniq_ips'], 1)
        self.assertEqual(len(stats.states[60].buckets), 1)
        bucket = stats.states[60].buckets[0]
        self.assertEqual(bucket[1], {'alice': 10000})
        self.assertEqual(bucket[2]['alice'], {'203.0.113.10': 10000})
        self.assertEqual(bucket[3]['alice'], {'node-a': 10000})

    def test_windows_expire_independently_and_preserve_counts(self):
        stats = watcher.RollingStats([5, 10], max_buckets=10)
        stats.add('alice', '203.0.113.1', 'node-a', now_ts=100.1)
        stats.add('alice', '203.0.113.1', 'node-a', now_ts=100.2)
        stats.add('alice', '203.0.113.2', 'node-b', now_ts=101.2)

        live = stats.snapshot(5, now_ts=101.5)[0]
        self.assertEqual(live['conns'], 3)
        self.assertEqual(live['uniq_ips'], 2)
        self.assertEqual(live['sources'], {'node-a': 2, 'node-b': 1})

        live_later = stats.snapshot(5, now_ts=106.2)[0]
        self.assertEqual(live_later['conns'], 1)
        self.assertEqual(live_later['ips'], {'203.0.113.2': 1})

        hourly = stats.snapshot(10, now_ts=106.2)[0]
        self.assertEqual(hourly['conns'], 3)
        self.assertEqual(hourly['uniq_ips'], 2)

    def test_adaptive_bucket_count_is_bounded_for_long_windows(self):
        stats = watcher.RollingStats([900, 18000], max_buckets=300)
        self.assertEqual(stats.states[900].bucket_seconds, 3.0)
        self.assertEqual(stats.states[18000].bucket_seconds, 60.0)

        for second in range(19000):
            stats.add('alice', '203.0.113.10', 'node-a', now_ts=float(second))

        stats.snapshot(900, now_ts=19000.0)
        stats.snapshot(18000, now_ts=19000.0)
        self.assertLessEqual(len(stats.states[900].buckets), 301)
        self.assertLessEqual(len(stats.states[18000].buckets), 301)

    def test_empty_window_after_expiration(self):
        stats = watcher.RollingStats([5], max_buckets=5)
        stats.add('alice', '203.0.113.1', 'node-a', now_ts=100.1)
        self.assertEqual(stats.snapshot(5, now_ts=106.1), [])


class ConfigurationTests(unittest.TestCase):
    def test_service_configuration_can_come_from_environment(self):
        env = {
            'BASE_URL': 'https://panel.example.test:8443',
            'ADMIN_USER': 'admin',
            'ADMIN_PASS': 'password with spaces and $characters',
            'LIVE_WINDOW': '900',
            'HOURLY_WINDOW': '18000',
        }
        with mock.patch.dict(os.environ, env, clear=True):
            args = watcher.parse_args([])
        self.assertEqual(args.base_url, env['BASE_URL'])
        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.password, env['ADMIN_PASS'])
        self.assertEqual(args.live_window, 900)
        self.assertEqual(args.hourly_window, 18000)

    def test_service_unit_does_not_put_credentials_in_argv(self):
        service = (MODULE_PATH.parent / 'marzban-watcher.service').read_text(encoding='utf-8')
        exec_line = next(line for line in service.splitlines() if line.startswith('ExecStart='))
        self.assertNotIn('--password', exec_line)
        self.assertNotIn('$ADMIN_PASS', exec_line)
        self.assertNotIn('--username', exec_line)
        self.assertNotIn('$ADMIN_USER', exec_line)
        self.assertNotIn('/bin/bash', exec_line)

        cli = (MODULE_PATH.parent / 'marzban-watcher').read_text(encoding='utf-8')
        self.assertNotIn('source "$ENV_FILE"', cli)


if __name__ == '__main__':
    unittest.main()
