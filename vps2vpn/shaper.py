"""Per-account speed limits with the kernel's traffic control, for the official (unpatched) cores.

How a limited account's traffic is found: Xray (Reality) and sing-box (TUIC) send that account's outgoing
connections with a socket mark of its own (MARK | user id). Upload leaves through the network card with that
mark, so an HTB class per account on the card's egress holds it to its speed. Download comes back on the same
connections: an nft rule copies the mark into the connection's conntrack entry, and the card's ingress restores
it (act_connmark) and redirects marked packets to an ifb device with the same per-account classes. Unmarked
traffic (everyone else) passes untouched.

Hysteria 2 has no per-user outbound settings, so a limited account is simply not served over Hysteria while
limits work here: the apps switch to Reality or TUIC. Where the kernel lacks these modules (OpenVZ/LXC and
other containers), limits are reported as unavailable and nothing is changed.
"""
import math
import shutil
import subprocess
import threading

from . import paths

MARK = 0x56000000           # high byte names our marks; the low 24 bits are the user id
MARK_MASK = 0xff000000
IFB = 'v2vifb0'
NFT_TABLE = 'vps2vpn_shape'
_ROOT = '1a5'               # our HTB handle on the card and on the ifb device

_lock = threading.Lock()
_state = {'applied': None, 'dev': '', 'error': '', 'available': None}


def mark(uid):
    return MARK | (int(uid) & 0xffffff)


def _run(cmd, stdin=None, timeout=15):
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def default_dev():
    for target in ('1.1.1.1', '2606:4700:4700::1111'):
        code, out = _run(['ip', '-o', 'route', 'get', target], timeout=5)
        if code == 0:
            words = out.split()
            if 'dev' in words and words.index('dev') + 1 < len(words):
                return words[words.index('dev') + 1]
    return ''


def available():
    """Whether limits can be enforced on this machine (tools, an ifb device and HTB). Cached."""
    if not paths.LIVE:
        return False
    with _lock:
        if _state['available'] is not None:
            return _state['available']
        ok = all(shutil.which(t) for t in ('tc', 'ip', 'nft'))
        if ok:
            code, _ = _run(['ip', 'link', 'add', IFB, 'type', 'ifb'])
            code2, out = _run(['ip', 'link', 'show', IFB])
            ok = code2 == 0
            if ok and code == 0:
                _run(['ip', 'link', 'del', IFB])       # only a probe; created again when a limit is set
        _state['available'] = ok
        if not ok:
            _state['error'] = 'tc/ifb not available on this kernel'
        return ok


def _unit_can_mark(name):
    """The core's unit grants CAP_NET_ADMIN (installs before 0.2.17 do not until install.sh runs again):
    without it Xray/sing-box could not set the mark and a limited account's connections would fail."""
    try:
        with open(paths._root + '/etc/systemd/system/%s.service' % name, encoding='utf-8') as f:
            return 'CAP_NET_ADMIN' in f.read()
    except OSError:
        return False


def active():
    """Limits are enforced here: the cores mark limited accounts and Hysteria leaves them out."""
    return available() and _unit_can_mark('vps2vpn-xray') and _unit_can_mark('vps2vpn-tuic')


def status():
    with _lock:
        state = {'available': bool(_state['available']), 'dev': _state['dev'], 'error': _state['error'],
                 'limited': len(_state['applied'] or {})}
    state['active'] = active()
    return state


def _kbit(mbps):
    return max(8, int(round(float(mbps) * 1000)))


def script(dev, limits):
    """tc -batch text for {uid: mbps} (both directions); '' when there is nothing to limit."""
    lines = []
    for d in (dev, IFB):
        lines += ['qdisc add dev %s root handle %s: htb default 1' % (d, _ROOT),
                  'class add dev %s parent %s: classid %s:1 htb rate 100gbit quantum 200000' % (d, _ROOT, _ROOT),
                  'qdisc add dev %s parent %s:1 fq_codel' % (d, _ROOT)]
        for i, uid in enumerate(sorted(limits), 16):
            rate = _kbit(limits[uid])
            minor = '%x' % i
            lines += ['class add dev %s parent %s: classid %s:%s htb rate %dkbit ceil %dkbit quantum 1514'
                      % (d, _ROOT, _ROOT, minor, rate, rate),
                      'qdisc add dev %s parent %s:%s fq_codel' % (d, _ROOT, minor),
                      'filter add dev %s parent %s: protocol all prio 1 handle 0x%x fw classid %s:%s'
                      % (d, _ROOT, mark(uid), _ROOT, minor)]
    lines += ['qdisc add dev %s handle ffff: ingress' % dev,
              # restore the connection's mark on the way in, then send only our marked packets to the ifb device
              'filter add dev %s parent ffff: protocol all prio 1 u32 match u32 0 0 action connmark continue' % dev,
              'filter add dev %s parent ffff: protocol all prio 2 handle 0x%x/0x%x fw action mirred egress redirect dev %s'
              % (dev, MARK, MARK_MASK, IFB)]
    return '\n'.join(lines) + '\n'


NFT_RULES = ('table inet %s\ndelete table inet %s\ntable inet %s {\n'
             ' chain out { type filter hook output priority mangle; policy accept;\n'
             '  meta mark & 0x%x == 0x%x ct mark set meta mark\n }\n}\n'
             % (NFT_TABLE, NFT_TABLE, NFT_TABLE, MARK_MASK, MARK))


def _teardown(dev):
    # only qdiscs we set up: a root or ingress qdisc someone else put on the card stays
    if dev and _ours(dev):
        _run(['tc', 'qdisc', 'del', 'dev', dev, 'root'])
        code, out = _run(['tc', 'filter', 'show', 'dev', dev, 'parent', 'ffff:'])
        # ours: redirects to our ifb device, or empty (a batch that failed between the qdisc and its filters)
        if code == 0 and (IFB in out or not out.strip()):
            _run(['tc', 'qdisc', 'del', 'dev', dev, 'ingress'])
    _run(['ip', 'link', 'del', IFB])
    _run(['nft', 'delete', 'table', 'inet', NFT_TABLE])


def _ours(dev):
    code, out = _run(['tc', 'qdisc', 'show', 'dev', dev])
    return code == 0 and ('htb %s:' % _ROOT) in out


def apply(limits, log=print, force=False):
    """Make the kernel hold each {uid: mbps} account to its speed. Idempotent; returns True when it holds."""
    limits = {int(k): float(v) for k, v in limits.items()
              if type(v) in (int, float) and math.isfinite(v) and 0 < v <= 100000}
    if not available():
        return not limits
    with _lock:
        dev = default_dev()
        same = (_state['applied'] == limits and _state['dev'] == dev)
        if same and not force and (not limits or _ours(dev)):
            return True
        old_dev = _state['dev']
        if old_dev and old_dev != dev:
            _teardown(old_dev)
        if not limits:
            if _state['applied'] or force or (dev and _ours(dev)):
                _teardown(dev)
            _state.update(applied={}, dev=dev, error='')
            return True
        if not dev:
            _state['error'] = 'no default network interface'
            return False
        _teardown(dev)
        steps = [(['ip', 'link', 'add', IFB, 'type', 'ifb'], None), (['ip', 'link', 'set', IFB, 'up'], None),
                 (['nft', '-f', '-'], NFT_RULES), (['tc', '-batch', '-'], script(dev, limits))]
        for cmd, stdin in steps:
            code, out = _run(cmd, stdin)
            if code != 0 and not (cmd[:3] == ['ip', 'link', 'add'] and 'exists' in out):
                _teardown(dev)
                _state.update(applied=None, dev=dev, error=(' '.join(cmd[:2]) + ': ' + out.strip())[:300])
                log('speed limits could not be applied: %s' % _state['error'])
                return False
        _state.update(applied=limits, dev=dev, error='')
        log('speed limits: %s' % ', '.join('u%d %g Mbps' % (k, v) for k, v in sorted(limits.items())))
        return True


def clear(log=print):
    with _lock:
        dev = _state['dev'] or default_dev()
    if available():
        apply({}, log, force=True)
    return dev
