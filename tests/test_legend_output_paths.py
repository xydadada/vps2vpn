"""The importer's output must not replace inputs reached through a directory alias."""
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools import legend_import


class LegendOutputPaths(unittest.TestCase):
    def make_inputs(self, root):
        original = root / 'original'
        original.mkdir()
        alias = root / 'alias'
        try:
            alias.symlink_to(original, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest('directory symlinks unavailable: %s' % error)
        (original / 'base.json').write_text(json.dumps({
            'format': 'vps2vpn-backup-1', 'settings': {}, 'users': [],
        }), encoding='utf-8')
        (original / 'settings.json').write_text('{"users": []}', encoding='utf-8')
        (original / 'template.json').write_text('{"rules": []}', encoding='utf-8')
        usage = sqlite3.connect(str(original / 'usage.sqlite3'))
        try:
            usage.execute('CREATE TABLE daily(user_id TEXT, cycle TEXT, day TEXT, '
                          'upload INTEGER, download INTEGER)')
            usage.commit()
        finally:
            usage.close()
        return original, alias

    def run_import(self, inputs, output):
        args = ['--base', str(inputs / 'base.json'), '--settings', str(inputs / 'settings.json'),
                '--usage', str(inputs / 'usage.sqlite3'), '--template', str(inputs / 'template.json'),
                '--now', '1700000000', '-o', str(output)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = legend_import.main(args)
        return code, stderr.getvalue()

    def test_directory_alias_cannot_replace_any_input(self):
        for inputs_use_alias in (False, True):
            for name in ('base.json', 'settings.json', 'usage.sqlite3', 'template.json'):
                with self.subTest(inputs_use_alias=inputs_use_alias, name=name):
                    with tempfile.TemporaryDirectory(prefix='legend-paths-') as tmp:
                        original, alias = self.make_inputs(Path(tmp))
                        before = {path: path.read_bytes() for path in original.iterdir()}
                        inputs, output_dir = (alias, original) if inputs_use_alias else (original, alias)
                        code, error = self.run_import(inputs, output_dir / name)
                        self.assertEqual(code, 2)
                        self.assertIn('-o 不能覆盖输入文件', error)
                        for path, data in before.items():
                            self.assertEqual(path.read_bytes(), data)

    def test_new_output_in_aliased_directory_remains_supported(self):
        with tempfile.TemporaryDirectory(prefix='legend-paths-') as tmp:
            original, alias = self.make_inputs(Path(tmp))
            before = {path: path.read_bytes() for path in original.iterdir()}
            output = alias / 'merged.json'
            code, error = self.run_import(original, output)
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['format'], 'vps2vpn-backup-1')
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
