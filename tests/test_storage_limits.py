import importlib.util
import json
import logging
import tempfile
import unittest
from pathlib import Path


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
                for index in range(25_000):
                    handle.write(json.dumps({'index': index, 'payload': 'x' * 96}) + '\n')

            original_size = path.stat().st_size
            max_bytes = 5 * 1024 * 1024 // 2
            self.assertGreater(original_size, max_bytes)
            self.assertLess(original_size - max_bytes, 1024 * 1024)

            changed = watcher.trim_jsonl_to_max_bytes(str(path), max_bytes)
            self.assertTrue(changed)
            self.assertLessEqual(path.stat().st_size, max_bytes)
            self.assertEqual([item.name for item in Path(tmp).iterdir()], ['history.jsonl'])

            with path.open('r', encoding='utf-8') as handle:
                retained = [json.loads(line) for line in handle if line.strip()]
            self.assertTrue(retained)
            self.assertEqual(retained[-1]['index'], 24_999)
            self.assertGreater(retained[0]['index'], 0)

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


if __name__ == '__main__':
    unittest.main()
