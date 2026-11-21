"""Regression tests for Telegram bot chat ownership verification."""
import unittest
import urllib.error
from unittest.mock import Mock, patch

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

    def test_bot_loop_rejects_malformed_result_without_crashing(self):
        settings = {'tg_token': 'bot-token', 'tg_chat': '42', 'tg_verified': True,
                    'tg_bot': True, 'setup_done': True}
        stop = Mock()
        stop.is_set.side_effect = [False, True]
        handle = Mock()
        with patch.object(notify.db, 'settings', return_value=settings), \
             patch.object(notify, '_bot_binding_active', return_value=True), \
             patch.object(notify, '_call', return_value={'ok': True, 'result': {'unexpected': 'shape'}}):
            notify.bot_loop(stop, handle, lambda line: None)
        handle.assert_not_called()
        stop.wait.assert_called_once_with(30)

    def test_bot_loop_skips_malformed_updates_and_runs_next_valid_command(self):
        settings = {'tg_token': 'bot-token', 'tg_chat': '42', 'tg_verified': True,
                    'tg_bot': True, 'setup_done': True}
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        handle = Mock(return_value=None)
        records = [None, 'invalid', {'update_id': True},
                   {'update_id': 3, 'message': 'bad'},
                   {'update_id': 4, 'message': {'text': 99}},
                   message(42, '/status', update_id=5)]
        with patch.object(notify.db, 'settings', return_value=settings), \
             patch.object(notify, '_bot_binding_active', return_value=True), \
             patch.object(notify, '_call', side_effect=[
                 {'ok': True, 'result': []},
                 {'ok': True, 'result': records},
             ]) as call:
            notify.bot_loop(stop, handle, lambda line: None)
        handle.assert_called_once_with('/status')
        self.assertEqual(call.call_count, 2)

    def test_bot_loop_advances_cursor_without_replaying_out_of_order_ids(self):
        settings = {'tg_token': 'bot-token', 'tg_chat': '42', 'tg_verified': True,
                    'tg_bot': True, 'setup_done': True}
        stop = Mock()
        stop.is_set.side_effect = [False, False, False, True]
        handle = Mock(return_value=None)
        records = [message(42, '/status', update_id=9),
                   message(42, '/replayed', update_id=8),
                   message(42, '/duplicate', update_id=9),
                   message(42, '/help', update_id=10)]
        with patch.object(notify.db, 'settings', return_value=settings), \
             patch.object(notify, '_bot_binding_active', return_value=True), \
             patch.object(notify, '_call', side_effect=[
                 {'ok': True, 'result': []},
                 {'ok': True, 'result': records},
                 {'ok': True, 'result': []},
             ]) as call:
            notify.bot_loop(stop, handle, lambda line: None)
        self.assertEqual([args.args[2].get('offset') for args in call.call_args_list],
                         [None, None, 11])
        self.assertEqual([args.args[0] for args in handle.call_args_list],
                         ['/status', '/help'])

    def test_bot_loop_backs_off_when_no_update_id_can_advance(self):
        settings = {'tg_token': 'bot-token', 'tg_chat': '42', 'tg_verified': True,
                    'tg_bot': True, 'setup_done': True}
        stop = Mock()
        stop.is_set.side_effect = [False, True]
        with patch.object(notify.db, 'settings', return_value=settings), \
             patch.object(notify, '_bot_binding_active', return_value=True), \
             patch.object(notify, '_call', return_value={
                 'ok': True, 'result': [None] * 100,
             }):
            notify.bot_loop(stop, Mock(), lambda line: None)
        stop.wait.assert_called_once_with(30)
    def _poll(self, replies, polls):
        settings = {'tg_token': 'bot-token', 'tg_chat': '42', 'tg_verified': True,
                    'tg_bot': True, 'setup_done': True}
        stop = Mock()
        stop.is_set.side_effect = [False] * polls + [True]
        handle = Mock(return_value=None)
        with patch.object(notify.db, 'settings', return_value=settings), \
             patch.object(notify, '_bot_binding_active', return_value=True), \
             patch.object(notify, '_call', side_effect=replies) as call:
            notify.bot_loop(stop, handle, lambda line: None)
        return [c.args[2].get('offset') for c in call.call_args_list], handle

    def test_oversized_update_id_never_becomes_the_cursor(self):
        offsets, handle = self._poll([
            {'ok': True, 'result': []},
            {'ok': True, 'result': [message(42, '/status', update_id=7),
                                    message(42, '/bogus', update_id=10 ** 100),
                                    message(42, '/help', update_id=8)]},
            {'ok': True, 'result': []},
        ], 3)
        self.assertEqual(offsets, [None, None, 9])
        self.assertEqual([c.args[0] for c in handle.call_args_list], ['/status', '/help'])

    def test_rejected_offset_reprimes_without_replaying_commands(self):
        bad_request = urllib.error.HTTPError('https://api.telegram.org', 400, 'Bad Request', {}, None)
        offsets, handle = self._poll([
            {'ok': True, 'result': []},
            {'ok': True, 'result': [message(42, '/status', update_id=5)]},
            bad_request,
            {'ok': True, 'result': [message(42, '/status', update_id=5)]},   # backlog after re-priming
            {'ok': True, 'result': [message(42, '/help', update_id=6)]},
        ], 5)
        self.assertEqual(offsets, [None, None, 6, None, 6])
        self.assertEqual([c.args[0] for c in handle.call_args_list], ['/status', '/help'])


if __name__ == '__main__':
    unittest.main()
