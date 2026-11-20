"""Alerts to the owner's Telegram: quota warnings, users paused, services down, IP changed, certificate trouble.

Setup in the panel: create a bot with @BotFather, paste its token, send the bot any message, then
press "Find my chat" - the panel reads the chat id from the bot's updates.
"""
import json
import http.client
import os
import threading
import time
import urllib.parse
import urllib.request

from . import db

API = 'https://api.telegram.org/bot%s/%s'
_recent = {}          # key -> monotonic cooldown expiry
_pending = set()
_send_lock = threading.Lock()


def _call(token, method, params=None, timeout=10):
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(API % (token, method), data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read((8 << 20) + 1)
    if len(raw) > 8 << 20:
        raise ValueError('Telegram response too large')
    result = json.loads(raw)
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise ValueError('Telegram request failed')
    return result


def send(text, key=None, every=6 * 3600, s=None):
    """Send unless the same `key` was sent within `every` seconds. Never raises."""
    s = s or db.settings()
    if not (s.get('tg_token') and s.get('tg_chat')):
        return False
    if key:
        with _send_lock:
            now = time.monotonic()
            for old in [k for k, expiry in _recent.items() if expiry <= now]:
                del _recent[old]
            if key in _pending or key in _recent:
                return False
            _pending.add(key)
    sent = False
    try:
        _call(s['tg_token'], 'sendMessage', {'chat_id': s['tg_chat'], 'text': msg,
                                             'disable_web_page_preview': 'true'})
        sent = True
        return True
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        if key:
            with _send_lock:
                _pending.discard(key)
                if sent:
                    _recent[key] = time.monotonic() + every


def find_chat(token):
    """The private chat id of whoever last messaged the bot; never select a group."""
    res = _call(token, 'getUpdates', {'limit': 20})
    for upd in reversed(res.get('result', [])):
        msg = upd.get('message') or upd.get('my_chat_member') or {}
        chat = msg.get('chat', {})
        if chat.get('type') == 'private' and isinstance(chat.get('id'), int) and chat['id'] > 0:
            return str(chat['id']), chat.get('username') or chat.get('title') or ''
    return None, None


def send_file(name, data, caption='', s=None):
    """Send a document (e.g. the daily backup) only to the owner's private chat. Never raises."""
    s = s or db.settings()
    chat = str(s.get('tg_chat') or '')
    if not (s.get('tg_token') and chat.isascii() and chat.isdecimal() and int(chat) > 0):
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
    except (OSError, ValueError, http.client.HTTPException):
        return False


def reply(s, chat, text):
    try:
        _call(s['tg_token'], 'sendMessage', {'chat_id': chat, 'text': text, 'disable_web_page_preview': 'true'})
    except (OSError, ValueError, http.client.HTTPException):
        pass


def bot_loop(stop, handle, log):
    """Long-poll the bot for commands. Only the owner's chat (the one saved when alerts were connected) is
    answered; everything else is ignored. `handle(text) -> reply text or ('file', name, bytes, caption)`."""
    offset, token, started_at = None, None, int(time.time())
    while not stop.is_set():
        s = db.settings()
        chat = str(s.get('tg_chat') or '')
        if not (s.get('tg_token') and chat.isascii() and chat.isdecimal() and int(chat) > 0
                and s.get('tg_bot') and s.get('setup_done')):
            offset, token = None, None
            stop.wait(30)
            continue
        if token != s['tg_token']:
            token, offset, started_at = s['tg_token'], None, int(time.time())
        try:
            params = {'timeout': 25 if primed else 0, 'allowed_updates': '["message"]'}
            if offset is None:
                params.update(offset=-1, timeout=0)  # only the tail of any backlog
            else:
                params['offset'] = offset
            res = _call(token, 'getUpdates', params, timeout=35)
        except (OSError, ValueError, http.client.HTTPException):
            stop.wait(30)
            continue
        first = not primed
        primed = True
        for upd in res.get('result', []):
            offset = upd['update_id'] + 1
            msg = upd.get('message') or {}
            if first and msg.get('date', 0) < started_at:
                continue              # old messages from before the panel started: do not act on them
            text = (msg.get('text') or '').strip()
            chat = msg.get('chat') or {}
            sender = msg.get('from') or {}
            if (str(chat.get('id')) != str(s['tg_chat']) or chat.get('type', 'private') != 'private'
                    or (sender.get('id') is not None and str(sender['id']) != str(s['tg_chat']))
                    or not text.startswith('/')):
                continue
            current = db.settings()
            if (not current.get('tg_bot') or not current.get('setup_done') or
                    any(current.get(k) != s.get(k) for k in ('tg_token', 'tg_chat'))):
                token, offset = None, None
                break
            try:
                out = handle(text)
            except Exception as e:      # a bad command must not stop the bot
                safe_err = str(e).replace(token, '***')
                out = 'error: %s' % safe_err
                log('telegram command failed: %s' % safe_err)
            if isinstance(out, tuple):
                send_file(out[1], out[2], out[3], s=s)
            elif out:
                reply(s, s['tg_chat'], out)
        if offset is None:
            offset = 0  # an empty initial response must not discard the next real command
