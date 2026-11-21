"""Alerts to the owner's Telegram: quota warnings, users paused, services down, IP changed, certificate trouble.

Setup in the panel: create a bot with @BotFather, paste its token, send the bot any message, then
press "Find my chat" - the panel reads the chat id from the bot's updates.
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

from . import db

API = 'https://api.telegram.org/bot%s/%s'
_recent = {}          # key -> (monotonic time sent, every), so one problem does not flood the chat
_recent_lock = threading.Lock()
_pending = set()          # alerts reserved during a blocking Telegram sendMessage request
MAX_TEXT = 4000


def _call(token, method, params=None, timeout=10):
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(API % (token, method), data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _target(s):
    """Settings with the Telegram target as it is NOW. Long jobs hold settings read minutes ago; if the owner
    has since switched Telegram off or to another chat, nothing may go to the old one (backups included)."""
    s = dict(s or db.settings())
    cur = db.settings()
    s['tg_token'], s['tg_chat'] = cur.get('tg_token'), cur.get('tg_chat')
    s['tg_verified'] = cur.get('tg_verified', False)
    return s


def send(text, key=None, every=6 * 3600, s=None):
    """Send unless the same `key` was sent within `every` seconds. Never raises."""
    s = _target(s)
    if not (s.get('tg_token') and s.get('tg_chat') and s.get('tg_verified') is True):
        return False
    now = time.monotonic()            # wall-clock jumps (NTP, manual set) must not mute or unmute alerts
    # A fresh verified owner binding must receive its first warning even when
    # the previous owner was sent an alert with the same key minutes ago.
    # A digest distinguishes bot credentials without keeping retired raw tokens
    # in the in-process deduplication cache after an owner rebind.
    bot_id = hashlib.sha256(s['tg_token'].encode('utf-8')).digest() if key else None
    recent_key = (bot_id, str(s['tg_chat']), key) if key else None
    if recent_key is not None:
        with _recent_lock:
            prev = _recent.get(recent_key)
            if recent_key in _pending or (prev is not None and now - prev[0] < every):
                return False
            # Reserve before making the network call: two concurrent workers
            # must not both deliver the same alert. Failed sends free the key.
            _pending.add(recent_key)
    try:
        # Message construction belongs inside the reservation's cleanup
        # boundary. An incomplete settings snapshot must not pin _pending.
        msg = ('[%s] %s' % (s.get('node_name') or 'vps2vpn', text))[:MAX_TEXT]
        result = _call(s['tg_token'], 'sendMessage', {'chat_id': s['tg_chat'], 'text': msg,
                                                     'disable_web_page_preview': 'true'})
        if not isinstance(result, dict) or result.get('ok') is not True:
            # HTTP success alone is not proof the Telegram Bot API accepted
            # the message; unsuccessful responses must remain retryable.
            return False
        if recent_key is not None:
            with _recent_lock:
                _recent[recent_key] = (now, every)
                if len(_recent) > 1000:
                    for k in [k for k, v in _recent.items() if now - v[0] >= max(v[1], 86400)]:
                        _recent.pop(k, None)
                    # High-cardinality alert keys or repeated rebindings may
                    # all be fresh. Expiry alone cannot cap this dictionary.
                    overflow = len(_recent) - 1000
                    if overflow > 0:
                        oldest = sorted(_recent, key=lambda k: _recent[k][0])
                        for k in oldest[:overflow]:
                            _recent.pop(k, None)
        return True
    except (OSError, ValueError):
        return False
    finally:
        if recent_key is not None:
            with _recent_lock:
                _pending.discard(recent_key)


def _owner_private_message(message, chat_id):
    """A command counts only from the owner's private chat, sent by the owner. A group's chat id names the
    group, not its admin: without the sender check any member could ask for /backup."""
    if not isinstance(message, dict):
        return False
    chat, sender = message.get('chat') or {}, message.get('from') or {}
    return (isinstance(chat, dict) and isinstance(sender, dict) and chat.get('type') == 'private'
            and chat.get('id') is not None and str(chat['id']) == str(chat_id)
            and str(sender.get('id')) == str(chat_id) and not sender.get('is_bot', False))


def find_chat(token, challenge):
    """Bind only a private chat whose user sent this panel's random pairing challenge.

    Telegram returns the oldest unconfirmed updates by default. A negative offset
    looks at the newest 100, so a busy bot's old backlog cannot conceal the
    fresh pairing command. The user explicitly initiates this operation.
    """
    if not re.fullmatch(r'[0-9a-f]{32}', str(challenge or '')):
        return None, None
    res = _call(token, 'getUpdates', {'limit': 100, 'offset': -100, 'allowed_updates': '["message"]'})
    if not isinstance(res, dict) or not res.get('ok', True):
        return None, None
    updates = res.get('result')
    if not isinstance(updates, list):
        return None, None
    for upd in reversed(updates):
        if not isinstance(upd, dict):
            continue
        msg = upd.get('message')
        if not isinstance(msg, dict) or msg.get('text') != '/bind ' + challenge:
            continue
        chat, sender = msg.get('chat') or {}, msg.get('from') or {}
        if not isinstance(chat, dict) or not isinstance(sender, dict):
            continue
        if (chat.get('type') != 'private' or not chat.get('id')
                or str(sender.get('id')) != str(chat['id']) or sender.get('is_bot')):
            continue
        return str(chat['id']), chat.get('username') or chat.get('first_name') or ''
    return None, None


def send_file(name, data, caption='', s=None):
    """Send a document (e.g. the daily backup) to the owner's chat. Never raises."""
    s = _target(s)
    if not (s.get('tg_token') and s.get('tg_chat') and s.get('tg_verified') is True):
        return False
    if isinstance(data, str):
        data = data.encode()
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', str(name or 'file'))[:120] or 'file'   # no header injection
    boundary = 'v2v' + os.urandom(12).hex()
    nl = b'\r\n'
    parts = []
    for k, v in (('chat_id', s['tg_chat']), ('caption', ('[%s] %s' % (s['node_name'], caption))[:1000])):
        parts += [b'--' + boundary.encode(), ('Content-Disposition: form-data; name="%s"' % k).encode(), b'',
                  str(v).encode()]
    parts += [b'--' + boundary.encode(),
              ('Content-Disposition: form-data; name="document"; filename="%s"' % safe_name).encode(),
              b'Content-Type: application/octet-stream', b'', data, b'--' + boundary.encode() + b'--', b'']
    req = urllib.request.Request(API % (s['tg_token'], 'sendDocument'), data=nl.join(parts),
                                 headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return bool(json.loads(r.read()).get('ok'))
    except (OSError, ValueError):
        return False


def _bot_binding_active(s):
    """A long-poll result or command response is valid only for the current owner binding."""
    cur = db.settings()
    return bool(cur.get('setup_done') and cur.get('tg_bot') and
                cur.get('tg_verified') is True and s.get('tg_verified') is True and
                cur.get('tg_token') and cur.get('tg_chat') and
                cur['tg_token'] == s.get('tg_token') and
                str(cur['tg_chat']) == str(s.get('tg_chat')))


def reply(s, chat, text):
    text = str(text or '')
    for i in range(0, len(text), MAX_TEXT):
        # A large response spans multiple Telegram messages: revalidate for
        # each chunk so disabling the bot also cancels the remaining text.
        if str(chat) != str(s.get('tg_chat')) or not _bot_binding_active(s):
            return
        try:
            _call(s['tg_token'], 'sendMessage', {'chat_id': chat, 'text': text[i:i + MAX_TEXT],
                                                 'disable_web_page_preview': 'true'})
        except (OSError, ValueError):
            break


def bot_loop(stop, handle, log):
    """Long-poll the bot for commands. Only the owner's chat (the one saved when alerts were connected) is
    answered; everything else is ignored. `handle(text) -> reply text or ('file', name, bytes, caption)`."""
    offset, token, primed = None, None, False
    while not stop.is_set():
        s = db.settings()
        if not (s.get('tg_token') and s.get('tg_chat') and s.get('tg_verified') is True
                and s.get('tg_bot') and s.get('setup_done')):
            offset, primed = None, False
            stop.wait(30)
            continue
        if token != s['tg_token']:
            token, offset, primed = s['tg_token'], None, False
        try:
            params = {'timeout': 25 if primed else 0, 'allowed_updates': '["message"]'}
            if offset is not None:
                params['offset'] = offset
            res = _call(token, 'getUpdates', params, timeout=35)
        except (OSError, ValueError):
            stop.wait(30)
            continue
        if not isinstance(res, dict) or not res.get('ok', True):
            stop.wait(30)              # e.g. 401 revoked token / 409 another poller: back off, do not spin
            continue
        # The admin might have disabled the bot or switched owner chats during
        # the 25-second poll. Never process the response under stale settings.
        if not _bot_binding_active(s):
            offset, primed = None, False
            continue
        batch = res.get('result') or []
        first = not primed
        # drain the backlog completely (getUpdates returns at most 100 per call) before acting on anything
        primed = primed or len(batch) < 100
        for upd in batch:
            # A change mid-batch must also cancel every remaining command.
            if not _bot_binding_active(s):
                offset, primed = None, False
                break
            offset = upd['update_id'] + 1
            if first:
                continue              # old messages from before the panel started: do not act on them
            msg = upd.get('message') or {}
            text = (msg.get('text') or '').strip()
            if not text.startswith('/') or not _owner_private_message(msg, s['tg_chat']):
                continue
            try:
                out = handle(text)
            except Exception as e:      # a bad command must not stop the bot
                safe_err = str(e).replace(token, '***')
                out = 'error: %s' % safe_err
                log('telegram command failed: %s' % safe_err)
            # Handlers (notably /doctor and /backup) may run long enough for
            # an administrator to revoke access before the response is sent.
            if not _bot_binding_active(s):
                offset, primed = None, False
                break
            if isinstance(out, tuple):
                send_file(out[1], out[2], out[3], s=s)
            elif out:
                reply(s, s['tg_chat'], out)
