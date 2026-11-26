"""Backups must describe one database revision while normal writers are active."""
import threading
from unittest import mock

from tests import test_unit as tu
from vps2vpn import db


class BackupSnapshot(tu.Base):
    def test_export_cannot_mix_settings_and_users_from_different_commits(self):
        uid = db.add_user('snapshot-user', note='before')
        db.set_settings(node_name='before')
        starting, committed = threading.Event(), threading.Event()
        failures = []

        def change_revision():
            starting.set()
            try:
                with db.transaction():
                    db.set_settings(node_name='after')
                    db.update_user(uid, note='after')
            except BaseException as error:
                failures.append(error)
            finally:
                committed.set()

        writer = threading.Thread(target=change_revision, daemon=True)
        read_settings = db.settings

        def pause_after_settings():
            result = read_settings()
            writer.start()
            self.assertTrue(starting.wait(2))
            committed.wait(0.2)
            return result

        try:
            with mock.patch.object(db, 'settings', side_effect=pause_after_settings):
                snapshot = db.export_all()
        finally:
            writer.join(5)
        self.assertFalse(writer.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(committed.is_set())
        self.assertEqual(snapshot['settings']['node_name'], 'before')
        self.assertEqual(snapshot['users'][0]['note'], 'before')
        self.assertEqual(db.user(uid)['note'], 'after')

    def test_export_can_run_inside_an_existing_transaction(self):
        with db.transaction():
            uid = db.add_user('pending-user')
            snapshot = db.export_all()
            self.assertEqual(snapshot['users'][0]['id'], uid)
        self.assertIsNotNone(db.user(uid))
