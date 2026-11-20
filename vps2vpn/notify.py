"""Alerts to the owner's Telegram: quota warnings, users paused, services down, IP changed, certificate trouble.

Setup in the panel: create a bot with @BotFather, paste its token, send the bot any message, then
press "Find my chat" - the panel reads the chat id from the bot's updates.
"""
import json
import os
import time
import urllib.parse
import urllib.request

from . import db

API = 'https://api.telegram.org/bot%s/%s'
_recent = {}          # key -> last time sent, so one problem does not flood the chat


def _call(token, method, params=None, timeout=10):
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(API % (token, method), data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def send(text, key=None, every=6 * 3600, s=None):
    """Send unless the same `key` was sent within `every` seconds. Never raises."""
    s = s or db.settings()
    if not (s.get('tg_token') and s.get('tg_chat')):
        return False
    now = time.time()
    if key and now - _recent.get(key, 0) < every:
        return False
    try:
        _call(s['tg_token'], 'sendMessage', {'chat_id': s['tg_chat'], 'text': '[%s] %s' % (s['node_name'], text),
                                             'disable_web_page_preview': 'true'})
        if key:
            _recent[key] = now
        return True
    except (OSError, ValueError):
        return False


def find_chat(token):
    """The chat id of whoever last messaged the bot."""
    res = _call(token, 'getUpdates', {'limit': 20})
    for upd in reversed(res.get('result', [])):
        msg = upd.get('message') or upd.get('my_chat_member') or {}
        chat = msg.get('chat', {})
        if chat.get('id'):
            return str(chat['id']), chat.get('username') or chat.get('title') or ''
    return None, None


def send_file(name, data, caption='', s=None):
    """Send a document (e.g. the daily backup) to the owner's chat. Never raises."""
    s = s or db.settings()
    if not (s.get('tg_token') and s.get('tg_chat')):
        return False
    boundary = 'v2v' + os.urandom(12).hex()
    nl = b'\r\n'
    parts = []
    for k, v in (('chat_id', s['tg_chat']), ('caption', ('[%s] %s' % (s['node_name'], caption))[:1000])):
        parts += [b'--' + boundary.encode(), ('Content-Disposition: form-data; name="%s"' % k).encode(), b'',
                  str(v).encode()]
    parts += [b'--' + boundary.encode(),
              ('Content-Disposition: form-data; name="document"; filename="%s"' % name).encode(),
              b'Content-Type: application/octet-stream', b'', data, b'--' + boundary.encode() + b'--', b'']
    req = urllib.request.Request(API % (s['tg_token'], 'sendDocument'), data=nl.join(parts),
                                 headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return bool(json.loads(r.read()).get('ok'))
    except (OSError, ValueError):
        return False


def reply(s, chat, text):
    try:
        _call(s['tg_token'], 'sendMessage', {'chat_id': chat, 'text': text, 'disable_web_page_preview': 'true'})
    except (OSError, ValueError):
        pass


def bot_loop(stop, handle, log):
    """Long-poll the bot for commands. Only the owner's chat (the one saved when alerts were connected) is
    answered; everything else is ignored. `handle(text) -> reply text or ('file', name, bytes, caption)`."""
    offset, token = None, None
    while not stop.is_set():
        s = db.settings()
        if not (s.get('tg_token') and s.get('tg_chat') and s.get('tg_bot') and s.get('setup_done')):
            offset = None
            stop.wait(30)
            continue
        if token != s['tg_token']:
            token, offset = s['tg_token'], None
        try:
            params = {'timeout': 25, 'allowed_updates': '["message"]'}
            if offset is not None:
                params['offset'] = offset
            res = _call(token, 'getUpdates', params, timeout=35)
        except (OSError, ValueError):
            stop.wait(30)
            continue
        first = offset is None
        for upd in res.get('result', []):
            offset = upd['update_id'] + 1
            if first:
                continue              # old messages from before the panel started: do not act on them
            msg = upd.get('message') or {}
            text = (msg.get('text') or '').strip()
            if str((msg.get('chat') or {}).get('id')) != str(s['tg_chat']) or not text.startswith('/'):
                continue
            try:
                out = handle(text)
            except Exception as e:      # a bad command must not stop the bot
                out = 'error: %s' % e
                log('telegram command failed: %s' % e)
            if isinstance(out, tuple):
                send_file(out[1], out[2], out[3], s=s)
            elif out:
                reply(s, s['tg_chat'], out)
