"""Fail closed when the Windows permissions command cannot secure a path."""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests.test_deploy import deploy


@unittest.skipIf(os.name == 'nt', 'uses a POSIX executable to simulate icacls exit codes')
class WindowsAclFailure(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.command = os.path.join(self.directory.name, 'icacls')
        self.exit_with(5)
        self.env = mock.patch.dict(os.environ, PATH=self.directory.name + os.pathsep + os.environ.get('PATH', ''),
                                   USERNAME='synthetic-test-user')
        self.env.start()
        self.addCleanup(self.env.stop)

    def exit_with(self, code):
        with open(self.command, 'w', encoding='utf-8') as file:
            file.write('#!/bin/sh\nexit %d\n' % code)
        os.chmod(self.command, 0o700)

    def test_nonzero_acl_status_is_an_error(self):
        with mock.patch.object(deploy.os, 'name', 'nt'):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                deploy.restrict(self.directory.name)
        self.assertEqual(raised.exception.returncode, 5)
        self.exit_with(0)
        with mock.patch.object(deploy.os, 'name', 'nt'):
            deploy.restrict(self.directory.name)

    def test_failed_private_directory_is_not_cached_for_a_retry(self):
        candidate = tempfile.mkdtemp(dir=self.directory.name)
        with mock.patch.object(deploy, 'WORK', None), \
                mock.patch.object(deploy.tempfile, 'mkdtemp', return_value=candidate), \
                mock.patch.object(deploy.os, 'name', 'nt'):
            with self.assertRaises(subprocess.CalledProcessError):
                deploy.work_dir()
            self.assertIsNone(deploy.WORK)
            self.assertFalse(os.path.exists(candidate))
        self.exit_with(0)
        with mock.patch.object(deploy, 'WORK', None), mock.patch.object(deploy.os, 'name', 'nt'):
            path = deploy.work_dir()
            self.addCleanup(shutil.rmtree, path, True)
            self.assertTrue(os.path.isdir(path))
            self.assertEqual(deploy.work_dir(), path)
