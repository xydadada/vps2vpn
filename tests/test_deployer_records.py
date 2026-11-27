"""Malformed saved metadata must not hide all other saved servers."""
import json
import os
import tempfile
import unittest
from unittest import mock

from tests.test_deploy import deploy


class SavedRecordShape(unittest.TestCase):
    def test_non_object_records_are_ignored_by_both_read_paths(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(deploy, 'RECORDS', directory):
            for value in (None, [], ['unexpected'], 'text', 42, True):
                with self.subTest(value=value):
                    with open(deploy.record_path('broken.example'), 'w', encoding='utf-8') as file:
                        json.dump(value, file)
                    self.assertEqual(deploy.load_record('broken.example'), {})
                    self.assertEqual(deploy.load_records(), [])

    def test_invalid_neighbors_do_not_hide_a_valid_saved_login(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(deploy, 'RECORDS', directory):
            valid = {'host': 'server.example', 'admin_password': 'synthetic-test-password'}
            for name, value in [('valid', valid), ('array', []), ('bad-host', {'host': ['server.example']}),
                                ('number-host', {'host': 3}), ('empty', {'host': ''})]:
                with open(os.path.join(directory, name + '.json'), 'w', encoding='utf-8') as file:
                    json.dump(value, file)
            with open(os.path.join(directory, 'truncated.json'), 'w', encoding='utf-8') as file:
                file.write('{')
            self.assertEqual(deploy.load_records(), [valid])
