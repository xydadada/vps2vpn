"""Several servers, one subscription.

Every install can be a *node*: it has a secret `node_key` and shows a join code (its panel address, the
key and its certificate fingerprint). Pasting that code into another install's panel makes that one the
*main server* for it. Once a minute the main server

  * pushes its users to each node (credentials + on/off); the node serves them next to its own users,
  * reads back how much each of those users has used there and adds it to their quota and history,
  * reads the node's public protocol settings, so subscriptions list the node's entries too.

Quotas, expiry and invites stay on the main server; a node only follows. The connection is HTTPS to the
node's panel, authenticated with the key and pinned to the node's certificate (a publicly trusted
certificate is accepted as well, so routine renewals never break the link).
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse

from . import certs, db, notify, paths, secure

SYNC_EVERY = 60
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
PASS_RE = re.compile(r'^[!-~]{6,128}$')   # printable ASCII, no spaces
PIN_RE = re.compile(r'^[0-9a-fA-F]{64}$')
ROLLBACK_CAP = 64 << 20                   # cap counter-drop recovery when idmap didn't change (prevents backup rollback spikes)
_wake = threading.Event()
_lock = threading.Lock()
_node_lock = threading.Lock()


# --- node side -------------------------------------------------------------------------
def public_info(s):
    """What a main server needs to build subscription entries for this server."""
    from .subscription import tls_info
    keys = ('node_name', 'public_host', 'public_ipv6', 'ipv6_nodes', 'reality_enabled', 'reality_port',
            'reality_target', 'reality_public_key', 'reality_short_id', 'hy2_enabled', 'hy2_port', 'hy2_hop',
            'hy2_hop_range', 'hy2_obfs', 'tuic_enabled', 'tuic_port')
    info = {k: s[k] for k in keys}
    info['tls'] = tls_info(s)
    from . import aicheck
    res = aicheck.latest()      # lets the main server send AI traffic to the server that suits it best
    info['ai'], info['ai_score'] = aicheck.summary(res), aicheck.score(res)
    return info


def join_code(s, base_url):
    crt, _ = certs.current(s.get('domain') or s['public_host'])
    try:
        pin = certs.fingerprint(crt)
    except OSError:
        pin = ''
    # The panel port always speaks HTTPS (the pin covers a self-signed certificate), even when the
    # subscription links use plain http:// because apps would refuse that certificate.
    if base_url.startswith('http://'):
        base_url = 'https://' + base_url[7:]
    raw = json.dumps({'u': '%s/%s' % (base_url, s['panel_path']), 'k': s['node_key'], 'p': pin, 'n': s['node_name']},
                     separators=(',', ':'))
    return 'v2v1.' + base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')


def parse_join_code(code):
    code = (code or '').strip()
    if not code.startswith('v2v1.'):
        raise ValueError('not a vps2vpn join code')
    try:
        d = json.loads(secure.b64url_decode(code[5:]))
        url = urllib.parse.urlsplit(d['u'])
        pin = d.get('p', '')
        if url.scheme != 'https' or not url.hostname or not isinstance(d['k'], str) or not d['k']:
            raise ValueError
        if not isinstance(pin, str) or (pin and not PIN_RE.fullmatch(pin)):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValueError('the join code is damaged; copy it again')
    return {'url': d['u'].rstrip('/'), 'key': d['k'], 'pin': pin.lower(), 'name': d.get('n') or url.hostname}


def _clean_label(text, limit=24):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(text or '')).strip()[:limit]


def _remote_name(uname, master, rid, skip_uid=None):
    base = ('%s@%s' % (uname, master))[:32]
    existing = db.user_by_name(base)
    if not existing or existing['id'] == skip_uid:
        return base
    suffix = '#%d' % rid
    cand = base[:max(1, 32 - len(suffix))] + suffix
    existing = db.user_by_name(cand)
    if not existing or existing['id'] == skip_uid:
        return cand
    i = 2
    while True:
        suffix = '#%d-%d' % (rid, i)
        cand = base[:max(1, 32 - len(suffix))] + suffix
        existing = db.user_by_name(cand)
        if not existing or existing['id'] == skip_uid:
            return cand
        i += 1


def _validated_sync_snapshot(body):
    """Validate the entire main-server snapshot before any account mutation."""
    if not isinstance(body, dict) or not isinstance(body.get('users'), list):
        raise ValueError('node sync requires a complete user list')
    if len(body['users']) > 20000:
        raise ValueError('node sync has too many users')
    master_raw, master_id = body.get('master') or 'main', body.get('master_id') or ''
    if not isinstance(master_raw, str) or not isinstance(master_id, str) or len(master_id) > 64:
        raise ValueError('invalid main-server identity')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in master_raw + master_id):
        raise ValueError('invalid main-server identity')
    master = _clean_label(master_raw, 24) or 'main'
    wanted, uuids = {}, set()
    for u in body['users']:
        if not isinstance(u, dict):
            raise ValueError('malformed node sync user')
        rid = u.get('id')
        if type(rid) is not int or not 0 < rid < (1 << 63) or rid in wanted:
            raise ValueError('duplicate or invalid remote account ID')
        name, uuid, secret, enabled = (u.get('name'), u.get('uuid'), u.get('hy2_pass'), u.get('enabled'))
        if not isinstance(name, str):
            raise ValueError('invalid remote user name')
        if not isinstance(uuid, str) or not UUID_RE.fullmatch(uuid) or uuid.lower() in uuids:
            raise ValueError('duplicate or invalid remote UUID')
        if not isinstance(secret, str) or not PASS_RE.fullmatch(secret):
            raise ValueError('invalid remote user credential')
        if type(enabled) not in (int, bool) or enabled not in (0, 1):
            raise ValueError('invalid remote enabled state')
        uuids.add(uuid.lower())
        wanted[rid] = {'name': _clean_label(name, 24) or 'u%d' % rid, 'uuid': uuid,
                       'hy2_pass': secret, 'enabled': int(enabled)}
    return master, master_id, wanted, uuids


def handle_sync(s, body, base_url=''):
    """Apply an authenticated snapshot atomically; never treat malformed rows as deletions."""
    master, master_id, wanted, uuids = _validated_sync_snapshot(body)
    with _node_lock, db.transaction():
        s = db.settings()
        if s['node_master_id'] and master_id != s['node_master_id']:
            return {'error': 'this server already belongs to main server "%s"; on it press "New join code" to free it'
                             % s['node_master'], 'conflict': True}
        all_users = db.users()
        if any(u['uuid'].lower() in uuids for u in all_users if not u['remote_id']):
            raise ValueError('remote UUID conflicts with a local account')
        changed = False
        mine = {u['remote_id']: u for u in db.users() if u['remote_id']}
        for rid, w in wanted.items():
            u = mine.get(rid)
            if u is None:
                name = _remote_name(w['name'], master, rid)
                uid = db.add_user(name, note='from main server %s' % master, remote_id=rid, uuid=w['uuid'],
                                  hy2_pass=w['hy2_pass'], enabled=w['enabled'],
                                  disabled_reason='' if w['enabled'] else 'remote')
                mine[rid] = db.user(uid)
                changed = True
            else:
                new_name = _remote_name(w['name'], master, rid, skip_uid=u['id'])
                core_changed = (u['uuid'], u['hy2_pass'], u['enabled']) != (w['uuid'], w['hy2_pass'], w['enabled'])
                if core_changed or u['name'] != new_name:
                    db.update_user(u['id'], name=new_name, uuid=w['uuid'], hy2_pass=w['hy2_pass'], enabled=w['enabled'],
                                   disabled_reason='' if w['enabled'] else 'remote')
                    u.update(name=new_name, uuid=w['uuid'], hy2_pass=w['hy2_pass'], enabled=w['enabled'])
                    if core_changed:
                        changed = True
        for rid, u in list(mine.items()):
            if rid not in wanted:
                db.delete_user(u['id'])
                del mine[rid]
                changed = True
        if s['node_master'] != master or (master_id and s['node_master_id'] != master_id):
            db.set_settings(node_master=master, node_master_id=master_id or s['node_master_id'])
        idmap = {str(rid): u['id'] for rid, u in mine.items()}
        traffic = {str(rid): [u['used_up'], u['used_down']] for rid, u in mine.items()}
    # Outside the transaction: the database lock is not held while the cores reload or health is sampled.
    if changed:
        from . import web
        web.apply_async()
    from . import system
    h = system.health()
    return {'ok': True, 'info': public_info(db.settings()), 'idmap': idmap, 'traffic': traffic,
            'health': {k: h.get(k) for k in ('load', 'cpus', 'mem_total', 'mem_used', 'uptime', 'rx_rate', 'tx_rate')},
            'version': __import__('vps2vpn').VERSION, 'at': int(time.time())}


# --- main-server side ---------------------------------------------------------------------
class SyncError(RuntimeError):
    pass


def _request(server, body, timeout=15):
    """POST to the node's sync endpoint over HTTPS with the pinned certificate. Returns (answer, pin)."""
    url = urllib.parse.urlsplit(server['url'])
    port = url.port or 443
    pin = (server.get('pin') or '').strip().lower()
    payload = json.dumps(body).encode()
    attempts = ('pin', 'public') if pin else ('public',)
    for attempt in attempts:
        if attempt == 'pin':
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()      # a certificate any browser would trust
        conn = http.client.HTTPSConnection(url.hostname, port, context=ctx, timeout=timeout)
        try:
            conn.connect()
            der = conn.sock.getpeercert(True)
            got = hashlib.sha256(der).hexdigest()
            if attempt == 'pin' and got != pin:
                conn.close()
                continue                             # maybe it renewed to a trusted certificate: try that
            conn.request('POST', url.path + '/api/node/sync', body=payload,
                         headers={'Content-Type': 'application/json', 'X-V2V': '1',
                                  'Authorization': 'Bearer ' + server['key']})
            r = conn.getresponse()
            data = r.read(8 << 20)
            if r.status != 200:
                try:
                    why = json.loads(data).get('error') or ''
                except ValueError:
                    why = data[:120].decode('utf-8', 'replace')
                raise SyncError('node answered %d: %s' % (r.status, why[:200]))
            return json.loads(data), got
        except ssl.SSLError as e:
            if attempt == 'public':
                raise SyncError('certificate changed and is not publicly trusted (%s); remove and re-add the server'
                                % e.reason)
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise SyncError('%s: %s' % (type(e).__name__, e))
        finally:
            conn.close()
    raise SyncError('certificate does not match; remove and re-add the server')


def push_users():
    return [{'id': u['id'], 'name': u['name'], 'uuid': u['uuid'], 'hy2_pass': u['hy2_pass'], 'enabled': bool(u['enabled'])}
            for u in db.users() if not u['remote_id']]


def _apply_sync_answer(server, ans, got_pin, log=print):
    """Apply a node's sync response to `server` and record traffic deltas in DB."""
    known = {u['id'] for u in db.users()}
    old_seen = server.get('seen') or {}
    seen = {}
    for k, v in old_seen.items():
        try:
            if int(k) in known and isinstance(v, (list, tuple)) and len(v) == 2:
                seen[str(k)] = (int(v[0]), int(v[1]))
        except (TypeError, ValueError):
            continue
    old_idmap = server.get('idmap') or {}
    new_idmap = ans.get('idmap') or {}
    deltas = []
    for rid, pair in (ans.get('traffic') or {}).items():
        try:
            uid = int(rid)
        except (TypeError, ValueError):
            continue
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        up, down = pair
        if isinstance(up, bool) or isinstance(down, bool) or not isinstance(up, int) or not isinstance(down, int):
            continue
        if up < 0 or down < 0:
            continue
        rid_key = str(rid)
        if uid in known and rid_key in seen:
            up0, down0 = seen[rid_key]
            id_changed = old_idmap.get(rid_key) != new_idmap.get(rid_key)
            if up >= up0:
                dup = up - up0
            elif id_changed or up <= ROLLBACK_CAP:
                dup = up
            else:
                dup = 0
                log('server %s user %s upload counter rolled back (%d -> %d); re-baselining' % (
                    server.get('name', ''), rid_key, up0, up))
            if down >= down0:
                ddown = down - down0
            elif id_changed or down <= ROLLBACK_CAP:
                ddown = down
            else:
                ddown = 0
                log('server %s user %s download counter rolled back (%d -> %d); re-baselining' % (
                    server.get('name', ''), rid_key, down0, down))
            if dup or ddown:
                deltas.append((uid, dup, ddown))
        if uid in known:
            seen[rid_key] = (up, down)
    if deltas:
        with db.transaction():
            for uid, dup, ddown in deltas:
                db.add_traffic(uid, dup, ddown)
    server.update(info=ans.get('info') or {}, idmap=new_idmap, seen=seen, health=ans.get('health') or {},
                  version=ans.get('version', ''), last_ok=int(time.time()), error='', fail_count=0, pin=got_pin)


def _record_sync_error(server, e):
    server.update(error=str(e)[:200], fail_count=server.get('fail_count', 0) + 1)
    if server['fail_count'] == 5:
        notify.send('server %s unreachable: %s / 子服务器 %s 连不上了' % (server['name'], e, server['name']),
                    key='node-down-' + server['id'], every=6 * 3600)


def sync_one(server, s=None, log=print):
    s = s or db.settings()
    try:
        ans, got_pin = _request(server, {'master': s['node_name'] or 'main', 'master_id': s['install_id'],
                                         'users': push_users()})
    except SyncError as e:
        _record_sync_error(server, e)
        return False
    _apply_sync_answer(server, ans, got_pin, log)
    return True


def sync_all(log=print):
    with _lock:
        s = db.settings()
        servers = [dict(x) for x in s['servers']]
        if not servers:
            return
        before = json.dumps([(x.get('info'), x.get('idmap')) for x in servers], sort_keys=True)
        payload = {'master': s['node_name'] or 'main', 'master_id': s['install_id'], 'users': push_users()}
    # Perform network I/O outside _lock so panel edits/restores never block on slow nodes.
    results = []
    for srv in servers:
        if not srv.get('enabled', True):
            continue
        try:
            ans, got_pin = _request(srv, payload)
            results.append((srv['id'], srv.get('url'), ans, got_pin, None))
        except SyncError as e:
            results.append((srv['id'], srv.get('url'), None, '', e))
    # Persist traffic + updated server state atomically per-server so a crash never double-counts
    # and concurrent removals/restores are never clobbered.
    for sid, surl, ans, got_pin, err in results:
        with _lock:
            cur_servers = db.settings()['servers']
            target = next((x for x in cur_servers if x['id'] == sid and x.get('url') == surl), None)
            if target is None:
                continue
            with db.transaction():
                if err is not None:
                    _record_sync_error(target, err)
                else:
                    _apply_sync_answer(target, ans, got_pin, log)
                db.set_settings(servers=cur_servers)
    final_servers = db.settings()['servers']
    if json.dumps([(x.get('info'), x.get('idmap')) for x in final_servers], sort_keys=True) != before:
        log('servers synced: %s' % ', '.join('%s %s' % (x['name'], 'ok' if not x.get('error') else 'FAILED')
                                            for x in final_servers))


def unique_name(name, s, skip=None):
    """Two servers in one city would both be "悉尼"; apps refuse duplicate entry names, so the next is "悉尼 2"."""
    taken = {s.get('node_name') or 'vps2vpn'} | {x['name'] for x in s['servers'] if x['id'] != skip}
    name = name[:24] or 'server'
    out, i = name, 2
    while out in taken:
        out = '%s %d' % (name[:21], i)
        i += 1
    return out


def _check_server_host(hostname):
    """Block loopback/private/link-local addresses in live mode to prevent SSRF via join codes."""
    if not paths.LIVE:
        return
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise ValueError('server address must be a public IP or domain')
        return
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError('cannot resolve server address: %s' % e)
    if not infos:
        raise ValueError('cannot resolve server address')
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise ValueError('server address must be a public IP or domain')


def add_server(code, name=''):
    j = parse_join_code(code)
    _check_server_host(urllib.parse.urlsplit(j['url']).hostname)
    s = db.settings()
    if any(x['url'] == j['url'] for x in s['servers']):
        raise ValueError('that server is already added')
    server = {'id': secrets.token_hex(4), 'name': unique_name(name or j['name'], s), 'url': j['url'], 'key': j['key'],
              'pin': j['pin'], 'enabled': True, 'info': {}, 'idmap': {}, 'seen': {}, 'added_at': int(time.time())}
    if not sync_one(server, s):
        raise ValueError('cannot reach that server: %s' % server['error'])
    with _lock:
        s2 = db.settings()
        if any(x['url'] == j['url'] for x in s2['servers']):
            raise ValueError('that server is already added')
        server['name'] = unique_name(name or j['name'], s2)
        db.set_settings(servers=s2['servers'] + [server])
    return server


def remove_server(sid):
    with _lock:
        db.set_settings(servers=[x for x in db.settings()['servers'] if x['id'] != sid])


def update_server(sid, **kv):
    with _lock:
        servers = db.settings()['servers']
        for x in servers:
            if x['id'] == sid:
                if 'name' in kv:
                    x['name'] = unique_name(str(kv['name']), db.settings(), sid) if str(kv['name']).strip() else x['name']
                if 'enabled' in kv:
                    x['enabled'] = bool(kv['enabled'])
        db.set_settings(servers=servers)


def view(s):
    """Server list for the panel, without keys."""
    out = []
    for x in s['servers']:
        info = x.get('info') or {}
        out.append({'id': x['id'], 'name': x['name'], 'host': info.get('public_host') or urllib.parse.urlsplit(x['url']).hostname,
                    'enabled': x.get('enabled', True), 'last_ok': x.get('last_ok', 0), 'error': x.get('error', ''),
                    'version': x.get('version', ''), 'health': x.get('health') or {},
                    'protocols': [p for p, k in (('reality', 'reality_enabled'), ('hy2', 'hy2_enabled'), ('tuic', 'tuic_enabled'))
                                  if info.get(k)], 'users': len(x.get('idmap') or {})})
    return out


def sync_soon():
    _wake.set()


def loop(stop, log=print):
    while not stop.is_set():
        _wake.wait(SYNC_EVERY)
        _wake.clear()
        if stop.is_set():
            return
        try:
            time.sleep(1)           # let a burst of edits settle
            sync_all(log)
        except Exception as e:      # never let the loop die
            log('server sync error: %r' % e)
