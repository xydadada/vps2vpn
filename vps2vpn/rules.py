"""Routing rule sets for clients, mirrored on the server so clients in China load them fast.

Rule data comes from MetaCubeX/meta-rules-dat (built from v2fly domain-list-community and
GeoIP data): `.mrs` files for Clash/mihomo, `.srs` files for sing-box, and `.list` text files that are
rewritten into Shadowrocket's rule-set syntax (DOMAIN-SUFFIX / DOMAIN / IP-CIDR lines).
"""
import ipaddress
import os
import threading
import time
import urllib.request

from . import paths

UPSTREAM = 'https://github.com/MetaCubeX/meta-rules-dat/raw/%s/geo/%s/%s.%s'
CDN = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@%s/geo/%s/%s.%s'

# name -> (kind, upstream file name). Order does not matter here; rule order lives in ROUTES.
SETS = {
    'private':        ('geosite', 'private'),
    'ads':            ('geosite', 'category-ads-all'),
    'ai':             ('geosite', 'category-ai-!cn'),
    'cn-download':    ('geosite', 'category-games@cn'),
    'steam-cn':       ('geosite', 'steam@cn'),
    'apple-cn':       ('geosite', 'apple-cn'),
    'microsoft-cn':   ('geosite', 'microsoft@cn'),
    'telegram':       ('geosite', 'telegram'),
    'proxy':          ('geosite', 'geolocation-!cn'),
    'cn':             ('geosite', 'cn'),
    'telegram-ip':    ('geoip', 'telegram'),
    'private-ip':     ('geoip', 'private'),
    'cn-ip':          ('geoip', 'cn'),
}

# Small, high-value lists kept inline (no download needed).
AD_EXCEPTIONS_PROXY = ['googletagmanager.com', 'google-analytics.com', 'app-measurement.com', 'clarity.ms']
CN_DIRECT_SUFFIX = ['steamcontent.com', 'steamserver.net', 'dl.steam.clngaa.com', 'download.windowsupdate.com',
                    'dl.delivery.mp.microsoft.com', 'officecdn.microsoft.com.edgesuite.net', 'mzstatic.com',
                    'cdn-apple.com', 'epicgames-download1-1251447533.file.myqcloud.com']

# AI services, kept inline so they are routed right even before the rule files are downloaded. They all go to
# the "AI" group, which stays on one server (see subscription.ai_servers).
AI_SUFFIX = ['anthropic.com', 'claude.ai', 'claude.com', 'claudeusercontent.com', 'clau.de', 'openai.com',
             'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'sora.com', 'gemini.google.com',
             'aistudio.google.com', 'generativelanguage.googleapis.com', 'notebooklm.google.com',
             'alkalimakersuite-pa.clients6.google.com', 'proactivebackend-pa.googleapis.com',
             'ai.google.dev', 'deepmind.google', 'x.ai', 'grok.com', 'perplexity.ai']


def route_plan(s):
    """Ordered (match, target) pairs shared by every client format.

    match: ('set', name) | ('suffix', domain) | ('final', None)
    target: 'proxy' | 'direct' | 'reject' | 'ai' | 'cn' | 'final'
    """
    plan = [('set', 'private', 'direct'), ('set', 'private-ip', 'direct')]
    # The owner's own lists come first: block, then direct, then proxy (a domain in two lists: first wins).
    seen = set()
    for key, to in (('custom_block', 'reject'), ('custom_direct', 'direct'), ('custom_proxy', 'proxy')):
        for d in s.get(key) or []:
            if d not in seen:
                seen.add(d)
                plan.append(('suffix', d, to))
    if s.get('block_ads', True):          # exceptions only matter when the ad list is in use
        for d in AD_EXCEPTIONS_PROXY:
            if d not in seen:
                seen.add(d)
                plan.append(('suffix', d, 'proxy'))
    if s.get('ai_group', True):
        for d in AI_SUFFIX:
            if d not in seen:
                seen.add(d)
                plan.append(('suffix', d, 'ai'))
    if s.get('block_ads', True):
        plan.append(('set', 'ads', 'reject'))
    if s.get('ai_group', True):
        plan.append(('set', 'ai', 'ai'))
    for d in CN_DIRECT_SUFFIX:
        if d not in seen:                 # the owner's own lists win over the built-in direct list
            seen.add(d)
            plan.append(('suffix', d, 'cn'))
    plan += [('set', 'cn-download', 'cn'), ('set', 'steam-cn', 'cn'), ('set', 'apple-cn', 'cn'),
             ('set', 'microsoft-cn', 'cn'), ('set', 'telegram', 'proxy'), ('set', 'telegram-ip', 'proxy'),
             ('set', 'proxy', 'proxy'), ('set', 'cn', 'cn'), ('set', 'cn-ip', 'cn'), ('final', None, 'final')]
    return plan


def used_sets(s):
    return [m[1] for m in route_plan(s) if m[0] == 'set']


FORMATS = ('clash', 'singbox', 'shadowrocket')
MAX_RULE_DOWNLOAD_BYTES = 50 << 20


def ext(fmt):
    return {'clash': 'mrs', 'singbox': 'srs', 'shadowrocket': 'list'}[fmt]


def branch(fmt):
    return 'sing' if fmt == 'singbox' else 'meta'


def to_shadowrocket(data, kind):
    """meta-rules-dat .list text -> Shadowrocket rule-set lines."""
    out = []
    for line in data.decode('utf-8', 'replace').splitlines():
        v = line.strip()
        if not v or v.startswith('#'):
            continue
        if kind == 'geoip':
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                continue
            out.append('%s,%s' % ('IP-CIDR' if net.version == 4 else 'IP-CIDR6', net))
        elif v.startswith('+.'):
            out.append('DOMAIN-SUFFIX,' + v[2:])
        elif v.startswith('.'):
            out.append('DOMAIN-SUFFIX,' + v[1:])
        elif all(c.isalnum() or c in '.-_' for c in v):
            out.append('DOMAIN,' + v)
        # anything else (regex/keyword forms) has no safe Shadowrocket equivalent and is skipped
    return ('\n'.join(out) + '\n').encode()


def _rule_payload(url, fmt):
    """Download a rule without accepting HTTP-200 errors or wrong binary data."""
    data = _fetch(url)
    # Both mirrors sometimes return branded error pages with HTTP 200.
    head = data[:256].lstrip().lower()
    if head.startswith((b'<!doctype', b'<html', b'<?xml', b'{"message"', b'{"error"')):
        raise OSError('rule download returned an error document')
    # Binary rules are identified by their actual on-disk magic, not by HTTP
    # status or a minimum size. An upstream plaintext "Access denied" with
    # status 200 could otherwise pass the size heuristic and destroy valid
    # .mrs/.srs rules currently used by clients.
    if fmt == 'clash' and not data.startswith(b'MRS!'):
        raise OSError('rule download has invalid MRS magic')
    if fmt == 'singbox' and not data.startswith(b'SRS'):
        raise OSError('rule download has invalid SRS magic')
    return data


def fetch_converted(name, fmt):
    try:
        data = _rule_payload(upstream_url(name, fmt, cdn=False), fmt)
    except OSError:
        data = _rule_payload(upstream_url(name, fmt, cdn=True), fmt)
    return to_shadowrocket(data, SETS[name][0]) if fmt == 'shadowrocket' else data


def local_file(name, fmt):
    return os.path.join(paths.RULES, '%s.%s' % (name, ext(fmt)))


def upstream_url(name, fmt, cdn=False):
    kind, fname = SETS[name]
    return (CDN if cdn else UPSTREAM) % (branch(fmt), kind, fname, ext(fmt))


def mrs_behavior(name):
    return 'ipcidr' if SETS[name][0] == 'geoip' else 'domain'


def _fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': 'vps2vpn-rules'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        # Reading precisely the limit would silently publish a truncated
        # binary rule set. A one-byte lookahead makes oversized responses a
        # recoverable error so the CDN fallback or old mirror remains in use.
        data = r.read(MAX_RULE_DOWNLOAD_BYTES + 1)
        if len(data) > MAX_RULE_DOWNLOAD_BYTES:
            raise OSError('rule download exceeds %d bytes' % MAX_RULE_DOWNLOAD_BYTES)
        return data


def refresh(log=print):
    """Download every rule set. A bad or suspiciously small download keeps the old file."""
    os.makedirs(paths.RULES, exist_ok=True)
    ok = 0
    for name in SETS:
        for fmt in FORMATS:
            dst = local_file(name, fmt)
            try:
                data = fetch_converted(name, fmt)
            except OSError as e:
                log('rules: %s.%s download failed: %s' % (name, ext(fmt), e))
                continue
            old = os.path.getsize(dst) if os.path.exists(dst) else 0
            if len(data) < 16 or (old and len(data) < old * 0.5):
                log('rules: %s.%s looks wrong (%d bytes, had %d), keeping the old copy' % (name, ext(fmt), len(data), old))
                continue
            paths.write_atomic(dst, data, 0o644)
            ok += 1
    return ok


def mirror_age():
    try:
        files = [f for f in os.listdir(paths.RULES) if not f.startswith('.') and not f.endswith('.tmp')]
    except OSError:
        return None
    mtimes = []
    for f in files:
        try:                              # a file can vanish between listdir and stat (refresh running)
            mtimes.append(os.path.getmtime(os.path.join(paths.RULES, f)))
        except OSError:
            continue
    return int(time.time() - min(mtimes)) if mtimes else None


_refresh_lock = threading.Lock()


def refresh_in_background(log=print):
    def go():
        if _refresh_lock.acquire(blocking=False):
            try:
                refresh(log)
            finally:
                _refresh_lock.release()
    threading.Thread(target=go, daemon=True).start()
