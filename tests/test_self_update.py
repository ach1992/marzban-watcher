import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install.sh'


class SelfUpdateTests(unittest.TestCase):
    def test_installer_never_overwrites_running_cli_in_place(self):
        text = INSTALLER.read_text(encoding='utf-8')
        self.assertIn(
            'atomic_replace_file "$STAGE_DIR/marzban-watcher" "$BIN_FILE" 0755',
            text,
        )
        self.assertIn(
            'atomic_replace_file "$BACKUP_DIR/marzban-watcher" "$BIN_FILE" 0755',
            text,
        )
        self.assertNotIn('cp "$STAGE_DIR/marzban-watcher" "$BIN_FILE"', text)
        self.assertNotIn('cp -a "$BACKUP_DIR/marzban-watcher" "$BIN_FILE"', text)

    def test_atomic_helper_can_replace_the_running_script_without_parser_corruption(self):
        text = INSTALLER.read_text(encoding='utf-8')
        match = re.search(r'(?ms)^atomic_replace_file\(\) \{\n.*?^\}\n', text)
        self.assertIsNotNone(match, 'atomic_replace_file helper not found')
        helper = match.group(0)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            running = tmp_path / 'runner.sh'
            replacement = tmp_path / 'replacement.sh'

            running.write_text(
                '#!/usr/bin/env bash\n'
                'set -euo pipefail\n'
                + helper
                + '\nupdate() {\n'
                '  atomic_replace_file "$1" "$0" 0755\n'
                '  echo UPDATE_DONE\n'
                '}\n'
                'cmd="${1:-status}"\n'
                'case "$cmd" in\n'
                '  update) update "$2" ;;\n'
                '  start|stop|restart) echo OLD_SERVICE ;;\n'
                '  *) echo OLD_OTHER ;;\n'
                'esac\n',
                encoding='utf-8',
            )
            replacement.write_text(
                '#!/usr/bin/env bash\n'
                'set -euo pipefail\n'
                'padding_one() { :; }\n'
                'padding_two() { :; }\n'
                'padding_three() { :; }\n'
                'cmd="${1:-status}"\n'
                'case "$cmd" in\n'
                '  update) echo NEW_UPDATE ;;\n'
                '  start|stop|restart) echo NEW_SERVICE ;;\n'
                '  *) echo NEW_OTHER ;;\n'
                'esac\n',
                encoding='utf-8',
            )
            running.chmod(0o755)
            replacement.chmod(0o755)

            updated = subprocess.run(
                [str(running), 'update', str(replacement)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(updated.returncode, 0, updated.stderr)
            self.assertIn('UPDATE_DONE', updated.stdout)

            syntax = subprocess.run(
                ['bash', '-n', str(running)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

            after = subprocess.run(
                [str(running), 'start'],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(after.returncode, 0, after.stderr)
            self.assertEqual(after.stdout.strip(), 'NEW_SERVICE')


if __name__ == '__main__':
    unittest.main()
