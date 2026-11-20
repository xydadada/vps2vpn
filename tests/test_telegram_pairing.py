"""Regression tests for Telegram bot chat ownership verification."""
import unittest
from unittest.mock import patch

from vps2vpn import notify


CODE = 'a' * 32
OTHER_CODE = 'b' * 32


def message(chat_id, text, chat_type='private', sender_id=None, is_bot=False, update_id=1):
    return {
        'update_id': update_id,
        'message': {
            'text': text,
            'chat': {'id': chat_id, 'type': chat_type, 'first_name': 'Owner'},
            'from': {'id': chat_id if sender_id is None else sender_id, 'is_bot': is_bot},
        },
    }


class TelegramPairing(unittest.TestCase):
    def test_only_exact_private_user_challenge_can_bind(self):
        updates = [
            message(99, '/start', update_id=1),
            message(-123, '/bind ' + CODE, chat_type='group', update_id=2),
            message(98, '/bind ' + OTHER_CODE, update_id=3),
            message(42, '/bind ' + CODE, update_id=4),
            message(99, '/start', update_id=5),  # newest unrelated user cannot steal the binding
        ]
        with patch.object(notify, '_call', return_value={'ok': True, 'result': updates}) as call:
            self.assertEqual(notify.find_chat('token', CODE), ('42', 'Owner'))
        self.assertEqual(call.call_args.args[:2], ('token', 'getUpdates'))
        self.assertEqual(call.call_args.args[2]['offset'], -100)
        self.assertEqual(call.call_args.args[2]['limit'], 100)

    def test_reject_group_sender_mismatch_and_bot(self):
        updates = [
            message(-1, '/bind ' + CODE, chat_type='supergroup'),
            message(42, '/bind ' + CODE, sender_id=100),
            message(42, '/bind ' + CODE, is_bot=True),
        ]
        with patch.object(notify, '_call', return_value={'ok': True, 'result': updates}):
            self.assertEqual(notify.find_chat('token', CODE), (None, None))

    def test_reject_nonmatching_and_missing_command(self):
        updates = [message(42, '/start ' + CODE), message(42, '/bind ' + OTHER_CODE)]
        with patch.object(notify, '_call', return_value={'ok': True, 'result': updates}):
            self.assertEqual(notify.find_chat('token', CODE), (None, None))

    def test_invalid_challenge_never_calls_telegram(self):
        with patch.object(notify, '_call') as call:
            for challenge in ('', 'short', 'A' * 32, 'x' * 32, 'a' * 31, 'a' * 33):
                self.assertEqual(notify.find_chat('token', challenge), (None, None))
        call.assert_not_called()

    def test_malformed_telegram_updates_fail_closed(self):
        bad = [None, 9, {'message': None}, {'message': {'text': '/bind ' + CODE,
                'chat': {'type': 'private', 'id': 42}, 'from': {}}}]
        with patch.object(notify, '_call', return_value={'ok': True, 'result': bad}):
            self.assertEqual(notify.find_chat('token', CODE), (None, None))
        with patch.object(notify, '_call', return_value={'ok': False, 'result': [message(42, '/bind ' + CODE)]}):
            self.assertEqual(notify.find_chat('token', CODE), (None, None))
        with patch.object(notify, '_call', return_value={'ok': True, 'result': {'unexpected': 'shape'}}):
            self.assertEqual(notify.find_chat('token', CODE), (None, None))



class TelegramLegacyCommandAuthorization(unittest.TestCase):
    def test_only_private_sender_may_run_commands_from_legacy_state(self):
        s = {'tg_token': '123456:' + 'A' * 35, 'tg_chat': '42',
             'tg_bot': True, 'setup_done': True}
        stop = __import__('threading').Event()
        handled = []
        polls = [
            {'ok': True, 'result': []},  # first poll drains prior messages
            {'ok': True, 'result': [
                message(42, '/backup', chat_type='group', update_id=11),
                message(42, '/backup', sender_id=99, update_id=12),
                message(42, '/backup', is_bot=True, update_id=13),
                message(42, '/status', update_id=14),
            ]},
        ]

        def fake_call(*args, **kwargs):
            answer = polls.pop(0)
            if not polls:
                stop.set()
            return answer

        with patch.object(notify.db, 'settings', return_value=s), \
             patch.object(notify, '_call', side_effect=fake_call), \
             patch.object(notify, 'reply') as reply, \
             patch.object(notify, 'send_file') as send_file:
            notify.bot_loop(stop, lambda cmd: handled.append(cmd) or 'ok', lambda *_: None)

        self.assertEqual(handled, ['/status'])
        reply.assert_called_once_with(s, '42', 'ok')
        send_file.assert_not_called()

    def test_preexisting_group_cannot_execute_or_receive_backups(self):
        group = {'tg_token': 'token', 'tg_chat': '-1001234', 'tg_bot': True,
                 'setup_done': True, 'node_name': 'server'}
        self.assertFalse(notify._owner_private_message(
            message(-1001234, '/backup', chat_type='supergroup')['message'],
            group['tg_chat']))
        with patch.object(notify.urllib.request, 'urlopen') as urlopen:
            self.assertFalse(notify.send_file('backup.json', b'passwords', s=group))
        urlopen.assert_not_called()

    def test_malformed_or_missing_sender_fails_closed(self):
        for value in (
                None, [], {}, {'chat': {'id': 42, 'type': 'private'}},
                {'chat': {'id': 42, 'type': 'private'},
                 'from': {'id': 42}},  # Telegram sender.is_bot is required
                {'chat': {'id': 42, 'type': 'private'},
                 'from': {'id': '42', 'is_bot': False}}):
            self.assertFalse(notify._owner_private_message(value, '42'))
        self.assertTrue(notify._owner_private_message(
            message(42, '/status')['message'], '42'))


if __name__ == '__main__':
    unittest.main()
