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
import json
import re
import secrets
import ssl
import threading
import time
import urllib.parse

from . import certs, db, notify, secure

SYNC_EVERY = 60
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
PASS_RE = re.compile(r'^[!-~]{6,128}$')   # printable ASCII, no spaces
_wake = threading.Event()
_lock = threading.Lock()


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
    crt, _ = certs.current(s['public_host'])
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
        if url.scheme != 'https' or not url.hostname or not d['k']:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValueError('the join code is damaged; copy it again')
    return {'url': d['u'].rstrip('/'), 'key': d['k'], 'pin': d.get('p', ''), 'name': d.get('n') or url.hostname}


def handle_sync(s, body, base_url=''):
    """Called on a node by its main server. Returns the node's answer."""
    master = str(body.get('master') or 'main')[:24]
    master_id = str(body.get('master_id') or '')[:64]
    if s['node_master_id'] and master_id and master_id != s['node_master_id']:
        # Two main servers would delete each other's accounts here every minute.
        return {'error': 'this server already belongs to main server "%s"; on it press "New join code" to free it'
                         % s['node_master'], 'conflict': True}
    wanted = {}
    for u in body.get('users') or []:
        try:
            w = {'name': str(u['name'])[:24], 'uuid': str(u['uuid']), 'hy2_pass': str(u['hy2_pass']),
                 'enabled': 1 if u.get('enabled') else 0}
            if UUID_RE.match(w['uuid']) and PASS_RE.match(w['hy2_pass']):   # a bad value would break the cores
                wanted[int(u['id'])] = w
        except (KeyError, TypeError, ValueError):
            continue
    changed = False
    mine = {u['remote_id']: u for u in db.users() if u['remote_id']}
    for rid, w in wanted.items():
        u = mine.get(rid)
        if u is None:
            name = '%s@%s' % (w['name'], master)
            if db.user_by_name(name):
                name = '%s#%d' % (name[:26], rid)
            uid = db.add_user(name[:32], note='from main server %s' % master, remote_id=rid, uuid=w['uuid'],
                              hy2_pass=w['hy2_pass'], enabled=w['enabled'],
                              disabled_reason='' if w['enabled'] else 'remote')
            mine[rid] = db.user(uid)
            changed = True
        elif (u['uuid'], u['hy2_pass'], u['enabled']) != (w['uuid'], w['hy2_pass'], w['enabled']):
            db.update_user(u['id'], uuid=w['uuid'], hy2_pass=w['hy2_pass'], enabled=w['enabled'],
                           disabled_reason='' if w['enabled'] else 'remote')
            changed = True
    for rid, u in list(mine.items()):
        if rid not in wanted:
            db.delete_user(u['id'])
            del mine[rid]
            changed = True
    if s['node_master'] != master or (master_id and s['node_master_id'] != master_id):
        db.set_settings(node_master=master, node_master_id=master_id or s['node_master_id'])
    if changed:
        from . import web
        web.apply_async()
    from . import system
    h = system.health()
    return {'ok': True, 'info': public_info(db.settings()),
            'idmap': {str(rid): u['id'] for rid, u in mine.items()},
            'traffic': {str(rid): [u['used_up'], u['used_down']] for rid, u in mine.items()},
            'health': {k: h.get(k) for k in ('load', 'cpus', 'mem_total', 'mem_used', 'uptime', 'rx_rate', 'tx_rate')},
            'version': __import__('vps2vpn').VERSION, 'at': int(time.time())}


# --- main-server side ---------------------------------------------------------------------
class SyncError(RuntimeError):
    pass


def _request(server, body, timeout=15):
    """POST to the node's sync endpoint over HTTPS with the pinned certificate. Returns (answer, pin)."""
    url = urllib.parse.urlsplit(server['url'])
    port = url.port or 443
    pin = server.get('pin', '')
    payload = json.dumps(body).encode()
    for attempt in ('pin', 'public'):
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
            if attempt == 'pin' and pin and got != pin:
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


def sync_one(server, s=None, log=print):
    s = s or db.settings()
    try:
        ans, got_pin = _request(server, {'master': s['node_name'] or 'main', 'master_id': s['install_id'],
                                         'users': push_users()})
    except SyncError as e:
        server.update(error=str(e)[:200], fail_count=server.get('fail_count', 0) + 1)
        if server['fail_count'] == 5:
            notify.send('server %s unreachable: %s / 子服务器 %s 连不上了' % (server['name'], e, server['name']),
                        key='node-down-' + server['id'], every=6 * 3600)
        return False
    seen = server.get('seen') or {}
    known = {u['id'] for u in db.users()}
    for rid, (up, down) in (ans.get('traffic') or {}).items():
        uid = int(rid)
        up0, down0 = seen.get(rid, (0, 0))
        # A lower count means the node lost the account (re-created, restored): count from zero again.
        dup = up - up0 if up >= up0 else up
        ddown = down - down0 if down >= down0 else down
        if uid in known and (dup or ddown) and rid in seen:
            db.add_traffic(uid, dup, ddown)
        seen[rid] = (up, down)
    server.update(info=ans.get('info') or {}, idmap=ans.get('idmap') or {}, seen=seen, health=ans.get('health') or {},
                  version=ans.get('version', ''), last_ok=int(time.time()), error='', fail_count=0, pin=got_pin)
    return True


def sync_all(log=print):
    with _lock:
        s = db.settings()
        servers = s['servers']
        if not servers:
            return
        before = json.dumps([(x.get('info'), x.get('idmap')) for x in servers], sort_keys=True)
        for server in servers:
            if server.get('enabled', True):
                sync_one(server, s, log)
        # write back only the server list (other settings may have changed meanwhile)
        db.set_settings(servers=servers)
        if json.dumps([(x.get('info'), x.get('idmap')) for x in servers], sort_keys=True) != before:
            log('servers synced: %s' % ', '.join('%s %s' % (x['name'], 'ok' if not x.get('error') else 'FAILED')
                                                for x in servers))


def unique_name(name, s, skip=None):
    """Two servers in one city would both be "悉尼"; apps refuse duplicate entry names, so the next is "悉尼 2"."""
    taken = {s.get('node_name') or 'vps2vpn'} | {x['name'] for x in s['servers'] if x['id'] != skip}
    name = name[:24] or 'server'
    out, i = name, 2
    while out in taken:
        out = '%s %d' % (name[:21], i)
        i += 1
    return out


def add_server(code, name=''):
    j = parse_join_code(code)
    s = db.settings()
    if any(x['url'] == j['url'] for x in s['servers']):
        raise ValueError('that server is already added')
    server = {'id': secrets.token_hex(4), 'name': unique_name(name or j['name'], s), 'url': j['url'], 'key': j['key'],
              'pin': j['pin'], 'enabled': True, 'info': {}, 'idmap': {}, 'seen': {}, 'added_at': int(time.time())}
    if not sync_one(server, s):
        raise ValueError('cannot reach that server: %s' % server['error'])
    with _lock:
        db.set_settings(servers=db.settings()['servers'] + [server])
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
