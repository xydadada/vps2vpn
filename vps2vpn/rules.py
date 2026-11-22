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
import zlib

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
MRS_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'  # outer zstd frame; Mihomo's MRS marker is inside

MAX_SRS_DECODE_BYTES = 256 << 20   # bounded streaming validation, not a rule-set decode


def _valid_mrs_zstd_frame(data):
    """Check the complete outer Zstandard frame boundaries without needing a zstd dependency.

    This cannot verify the compressed contents or its checksum; those remain
    the rule client's job. It does reject truncated frames, reserved block
    types and HTTP-200 error bodies that merely start with the magic bytes.
    """
    if len(data) < 9:
        return False
    pos, blocks = 0, 0
    while pos < len(data):
        if data[pos:pos + 4] != MRS_ZSTD_MAGIC:
            return False
        pos += 4
        if pos >= len(data):
            return False
        descriptor = data[pos]
        pos += 1
        if descriptor & 0x08:       # reserved frame-header bit
            return False
        single = bool(descriptor & 0x20)
        dict_bytes = (0, 1, 2, 4)[descriptor & 3]
        flag = descriptor >> 6
        fcs_bytes = (1 if single else 0) if flag == 0 else (2, 4, 8)[flag - 1]
        hdr = dict_bytes + fcs_bytes + (0 if single else 1)
        if pos + hdr > len(data):
            return False
        pos += hdr
        while True:
            if pos + 3 > len(data) or blocks >= 100000:
                return False
            block = int.from_bytes(data[pos:pos + 3], 'little')
            pos += 3
            blocks += 1
            kind = (block >> 1) & 3
            if kind == 3:          # reserved block type
                return False
            payload_size = 1 if kind == 1 else block >> 3  # RLE has only one stored byte
            if pos + payload_size > len(data):
                return False
            pos += payload_size
            if block & 1:          # last block
                break
        if descriptor & 4:         # optional 4-byte content checksum
            if pos + 4 > len(data):
                return False
            pos += 4
    return pos == len(data)


def _valid_srs_zlib_stream(data):
    """Check SRS version and zlib checksum without allocating its expanded rule set."""
    if len(data) <= 6 or not data.startswith(b'SRS') or data[3] < 1:
        return False
    try:
        decoder = zlib.decompressobj()
        total = 0
        for offset in range(4, len(data), 65536):
            chunk = memoryview(data)[offset:offset + 65536]
            chunk_end = offset + len(chunk)
            while chunk:
                before = len(chunk)
                decoded = decoder.decompress(chunk, 1 << 20)
                total += len(decoded)
                if total > MAX_SRS_DECODE_BYTES:
                    return False
                if decoder.eof:
                    return not decoder.unused_data and chunk_end == len(data)
                chunk = decoder.unconsumed_tail
                if len(chunk) == before and not decoded:
                    return False
        return decoder.eof and not decoder.unused_data
    except zlib.error:
        return False



def ext(fmt):
    return {'clash': 'mrs', 'singbox': 'srs', 'shadowrocket': 'list'}[fmt]


def branch(fmt):
    return 'sing' if fmt == 'singbox' else 'meta'


def _plain_domain(v):
    return bool(v) and not v.startswith('.') and all(c.isalnum() or c in '.-_' for c in v)


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
        elif v.startswith('+.') or v.startswith('.'):
            name = v[2:] if v.startswith('+.') else v[1:]
            if _plain_domain(name):          # a comma would add a policy field to the Shadowrocket rule
                out.append('DOMAIN-SUFFIX,' + name)
        elif _plain_domain(v):
            out.append('DOMAIN,' + v)
        # anything else (regex/keyword forms) has no safe Shadowrocket equivalent and is skipped
    return ('\n'.join(out) + '\n').encode()


def _rule_payload(url, fmt):
    """Reject 200 error documents and wrong binary framing before cache publication."""
    data = _fetch(url)
    # Both mirrors sometimes return a branded error page with HTTP 200. That
    # is never a valid .mrs/.srs or a MetaCubeX text rule list. Avoid silently
    # replacing the last working rules with an HTML/JSON error response.
    head = data[:256].lstrip().lower()
    if head.startswith((b'<!doctype', b'<html', b'<?xml', b'{"message"', b'{"error"')):
        raise OSError('rule download returned an error document')
    # Mihomo's .mrs is a Zstandard stream: its inner MRS + version marker is
    # written via zstd.NewWriter and is NOT the on-disk file prefix.
    # sing-box writes 'SRS' + version directly before its zlib payload.
    # These are framing checks, not substitutes for full client-side parsing.
    if fmt == 'clash' and not _valid_mrs_zstd_frame(data):
        raise OSError('invalid or truncated MRS Zstandard frame')
    if fmt == 'singbox' and not _valid_srs_zlib_stream(data):
        raise OSError('invalid or truncated SRS zlib stream')
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


def incomplete():
    """True while some rule file was never fetched (a first download that got only part of them)."""
    return any(not os.path.exists(local_file(name, fmt)) for name in SETS for fmt in FORMATS)


_refresh_lock = threading.Lock()


def refresh_in_background(log=print):
    def go():
        if _refresh_lock.acquire(blocking=False):
            try:
                refresh(log)
            finally:
                _refresh_lock.release()
    threading.Thread(target=go, daemon=True).start()
