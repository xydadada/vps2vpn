"""Shared accounts keep their current usage when the owner changes the reset day."""
import datetime as dt
import json
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import clock, db, jobs, members, secure


def timestamp(text):
    return int(dt.datetime.fromisoformat(text).replace(tzinfo=dt.timezone.utc).timestamp())


class _Web(tu.Web):
    pass


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class SharedResetPeriod(_Web):
    def setUp(self):
        super().setUp()
        self.addCleanup(db.set_settings, time_zone=db.settings()['time_zone'])
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('REDACTED-password'), time_zone='UTC')
        status, _, _ = self.req('POST', self.pp + '/api/login',
                                {'username': 'admin', 'password': 'REDACTED-password'})
        self.assertEqual(status, 200)

    def tree(self, reset_day, last_reset):
        root = db.add_user('parent', 100, reset_day=reset_day)
        child = db.add_user('child', 20, reset_day=reset_day, invited_by=root, invite_deduct=20)
        grandchild = db.add_user('grandchild', 5, reset_day=reset_day, invited_by=child, invite_deduct=5)
        for uid in (root, child, grandchild):
            db.update_user(uid, last_reset=last_reset, used_down=1 << 30, extra_gb=2)
        return root, child, grandchild

    def change(self, uid, reset_day):
        status, body, _ = self.req('POST', self.pp + '/api/users/%d/save' % uid, {'reset_day': reset_day})
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def assert_usage(self, ids, used, extra):
        for uid in ids:
            with self.subTest(user=uid):
                row = db.user(uid)
                self.assertEqual((row['used_down'], row['extra_gb']), (used, extra))

    def test_earlier_day_preserves_every_generation_until_next_month(self):
        with mock.patch('time.time', return_value=timestamp('2026-11-10T12:00:00')):
            ids = self.tree(20, '2026-10')
            response = self.change(ids[0], 5)
            self.assertEqual(response['period_ends'], '2026-12-05')
            self.assert_usage(ids, 1 << 30, 2)
            self.assertTrue(all(db.user(uid)['last_reset'] == '2026-11' for uid in ids))
            jobs.enforce(timestamp('2026-12-04T23:59:59'))
            self.assert_usage(ids, 1 << 30, 2)
            jobs.enforce(timestamp('2026-12-05T00:00:01'))
            self.assert_usage(ids, 0, 0)

    def test_later_day_does_not_skip_this_month_for_descendants(self):
        with mock.patch('time.time', return_value=timestamp('2026-11-10T12:00:00')):
            ids = self.tree(1, '2026-11')
            response = self.change(ids[0], 20)
            self.assertEqual(response['period_ends'], '2026-11-20')
            self.assert_usage(ids, 1 << 30, 2)
            jobs.enforce(timestamp('2026-11-20T00:00:01'))
            self.assert_usage(ids, 0, 0)

    def test_unchanged_descendant_schedule_keeps_its_due_reset(self):
        with mock.patch('time.time', return_value=timestamp('2026-11-10T12:00:00')):
            ids = self.tree(20, '2026-10')
            db.update_user(ids[1], reset_day=5)
            members.propagate_lifetime(ids[0], None, 5)
            self.assertEqual(db.user(ids[1])['last_reset'], '2026-10')
            self.assertTrue(jobs.monthly_reset(db.user(ids[1]))[0])
            self.assertEqual(db.user(ids[2])['last_reset'], '2026-11')

    def test_unused_member_code_uses_the_current_parent_schedule(self):
        with mock.patch('time.time', return_value=timestamp('2026-11-10T12:00:00')):
            root = db.add_user('parent', 100, reset_day=20)
            code = members.create_invite('member', 10, 30, inviter=root)['code']
            self.change(root, 5)
            uid = members.register(code, 'new-child', 'REDACTED-password')
            self.assertEqual(db.user(uid)['reset_day'], 5)
            self.assertEqual(clock.date_of(clock.next_reset(db.user(uid)['reset_day'])), '2026-12-05')

    def test_admin_code_retains_its_own_schedule(self):
        with mock.patch('time.time', return_value=timestamp('2026-11-10T12:00:00')):
            code = members.create_invite('admin', 10, 30, reset_day=20)['code']
            uid = members.register(code, 'admin-child', 'REDACTED-password')
            self.assertEqual(db.user(uid)['reset_day'], 20)


if __name__ == '__main__':
    unittest.main()
