"""Tests for the one-click path: setup without the web wizard, what the deployer remembers, the firewall
check from the outside, and adding a second server to the first through the panel API.

    python -m unittest tests.test_deploy
"""
import base64
import hashlib
import http.client
import http.server
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import __main__ as cli, cluster, db, secure, web

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'deploy'))
import deploy  # noqa: E402


class QuickSetup(tu.Base):
    def test_finishes_setup_and_returns_login(self):
        with open(web.SETUP_TOKEN_FILE, 'w') as f:
            f.write('tok')
        a = cli.quick_setup()
        s = db.settings()
        self.assertTrue(s['setup_done'])
        self.assertEqual(a['admin_user'], 'admin')
        self.assertGreaterEqual(len(a['admin_password']), 12)
        self.assertTrue(secure.check_password(a['admin_password'], s['admin_hash']))
        self.assertEqual([u['name'] for u in db.users()], ['我'])
        self.assertFalse(os.path.exists(web.SETUP_TOKEN_FILE))        # the setup link stops working

    def test_result_info(self):
        cli.quick_setup()
        info = cli.result_info(db.settings())
        u = db.users()[0]
        self.assertTrue(info['sub_url'].endswith('/s/' + u['sub_token']))
        self.assertTrue(info['qr_url'].endswith('/qr.svg'))
        self.assertTrue(info['links']['clash'].startswith('clash://install-config?url='))
        self.assertEqual(len(info['pin']), 64)
        self.assertEqual(cluster.parse_join_code(info['join_code'])['key'], db.settings()['node_key'])
        names = [c[2] for c in info['checks']]
        self.assertEqual(names[0], '管理面板')
        self.assertEqual([c[0] for c in info['checks']], ['tcp', 'tcp', 'udp', 'udp'])
        self.assertNotIn('admin_password', info)


class Records(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._old = deploy.RECORDS
        deploy.RECORDS = self.dir

    def tearDown(self):
        deploy.RECORDS = self._old
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_upgrade_keeps_saved_password(self):
        job = {'host': '203.0.113.9', 'user': 'root', 'port': 22}
        first = {'auto': {'admin_user': 'admin', 'admin_password': 'secret-1', 'panel': 'https://a/p/', 'join_code': 'v2v1.a'}}
        deploy.save_record(job['host'], deploy.merge_record(job, first))
        later = {'auto': {'panel': 'https://a/p/', 'join_code': 'v2v1.b'}, 'cloud': 'AWS Lightsail'}
        rec = deploy.merge_record(job, later)
        self.assertEqual(rec['admin_password'], 'secret-1')
        self.assertEqual(rec['join_code'], 'v2v1.b')
        p = deploy.save_record(job['host'], rec)
        self.assertEqual(deploy.load_records()[0]['host'], '203.0.113.9')
        if os.name != 'nt':
            self.assertEqual(os.stat(p).st_mode & 0o077, 0)


class PortCheck(unittest.TestCase):
    def test_tcp_and_quic_probe(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        udp.settimeout(5)
        seen = []

        def answer():               # what a QUIC server does with an unknown version
            try:
                d, addr = udp.recvfrom(2048)
                seen.append(len(d))
                udp.sendto(bytes([0x80]) + b'\0\0\0\0' + d[5:23] + b'\0\0\0\1', addr)
            except OSError:
                pass
        t = threading.Thread(target=answer, daemon=True)
        t.start()
        try:
            out = deploy.check_ports('127.0.0.1', [['tcp', srv.getsockname()[1], 'panel'],
                                                   ['udp', udp.getsockname()[1], 'hy2']], tries=1)
            self.assertEqual([c['ok'] for c in out], [True, True])
            self.assertEqual(seen, [1200])               # QUIC needs a full-size first packet
            with socket.socket() as closed:
                closed.bind(('127.0.0.1', 0))
                port = closed.getsockname()[1]
            self.assertFalse(deploy.tcp_open('127.0.0.1', port, timeout=2))
        finally:
            srv.close()
            udp.close()
            t.join(2)


class JoinMain(tu.Base):
    """The deployer logs in to the first server's panel (pinned certificate) and adds the second one."""
    def test_login_and_add(self):
        web._fails.clear()
        a = cli.quick_setup()
        s = db.settings()
        srv = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        orig_apply = web.apply_async
        web.apply_async = lambda force=False: None
        try:
            port = srv.server_address[1]
            rec = cli.result_info(s)
            main = {'panel': 'https://127.0.0.1:%d/%s/' % (port, s['panel_path']), 'pin': rec['pin'],
                    'admin_user': 'admin', 'admin_password': a['admin_password']}
            added = []
            orig = cluster.add_server
            cluster.add_server = lambda code, name='': added.append((code, name)) or {'id': 'x', 'name': name}
            try:
                self.assertEqual(deploy.join_main(main, {'join_code': 'v2v1.code'}, '198.51.100.7'), 'ok')
            finally:
                cluster.add_server = orig
            self.assertEqual(added, [('v2v1.code', '198.51.100.7')])
            with self.assertRaises(deploy.PanelError):
                deploy.join_main(dict(main, pin='00' * 32), {'join_code': 'x'}, 'y')     # someone else's certificate
            with self.assertRaises(deploy.PanelError):
                deploy.join_main(dict(main, admin_password='wrong-one'), {'join_code': 'x'}, 'y')
        finally:
            web.apply_async = orig_apply
            srv.shutdown()
            srv.server_close()
            t.join(5)


class AICheck(tu.Base):
    """The AI availability check, with the network replaced by canned answers."""
    def fake(self, answers):
        from vps2vpn import aicheck
        orig = aicheck._req

        def req(url, method='GET', data=None, headers=None, timeout=12):
            for key, ans in answers.items():
                if key in url:
                    return ans
            return 0, {}, b'', url
        aicheck._req = req
        self.addCleanup(setattr, aicheck, '_req', orig)

    US_OK = {
        'cdn-cgi/trace': (200, {}, b'ip=1.2.3.4\nloc=US\n', ''),
        'ipinfo.io': (200, {}, json.dumps({'country': 'US', 'city': 'Seattle', 'org': 'AS16509 Amazon'}).encode(), ''),
        'ip-api.com': (200, {}, json.dumps({'status': 'success', 'countryCode': 'US', 'hosting': True}).encode(), ''),
        'claude.ai/': (403, {'cf-mitigated': 'challenge'}, b'Just a moment', 'https://claude.ai/'),
        'api.anthropic.com': (401, {}, b'{"type":"error","error":{"type":"authentication_error"}}', ''),
        'api.openai.com': (200, {}, b'{"cookie_requirements":"none"}', ''),
        'gemini.google.com': (200, {}, b'<html>', ''),
    }

    def test_all_usable(self):
        from vps2vpn import aicheck
        self.fake(self.US_OK)
        res = aicheck.run()
        self.assertEqual(res['country'], 'US')
        self.assertEqual({k: v['status'] for k, v in res['sites'].items()},
                         {'claude': 'ok', 'claude_api': 'ok', 'chatgpt': 'ok', 'gemini': 'ok'})
        self.assertIn('人机验证', res['sites']['claude']['note'])
        self.assertEqual(aicheck.summary(res), 'Claude ✓  ChatGPT ✓  Gemini ✓')
        self.assertEqual(aicheck.score(res), 4)
        self.assertEqual(res['ip']['kind'], 'hosting')
        self.assertEqual(aicheck.place_name(res), '西雅图')
        self.assertEqual(aicheck.latest()['at'], res['at'])          # saved for the panel

    def test_blocked_region(self):
        from vps2vpn import aicheck
        ans = dict(self.US_OK)
        ans['cdn-cgi/trace'] = (200, {}, b'loc=HK\n', '')
        ans['claude.ai/'] = (200, {}, b'', 'https://claude.ai/app-unavailable-in-region')
        ans['api.anthropic.com'] = (403, {}, b'{"error":{"type":"forbidden","message":"Request not allowed"}}', '')
        ans['api.openai.com'] = (403, {}, b'{"error":{"code":"unsupported_country"}}', '')
        self.fake(ans)
        res = aicheck.run()
        self.assertEqual(res['sites']['claude']['status'], 'blocked')
        self.assertEqual(res['sites']['claude_api']['status'], 'blocked')
        self.assertEqual(res['sites']['chatgpt']['status'], 'blocked')
        self.assertEqual(res['sites']['gemini']['status'], 'blocked')
        self.assertEqual(aicheck.summary(res), 'Claude ✗  ChatGPT ✗  Gemini ✗')
        self.assertEqual(aicheck.score(res), 0)
        self.assertTrue(any('Claude' in a for a in res['advice']))

    def test_offline_and_changes(self):
        from vps2vpn import aicheck
        self.fake({})
        res = aicheck.run()
        self.assertEqual({v['status'] for v in res['sites'].values()}, {'unreachable'})
        self.fake(self.US_OK)
        new = aicheck.run()
        diff = aicheck.changed(res, new)
        self.assertEqual(len(diff), 4)
        self.assertEqual(aicheck.changed(new, new), [])
        self.assertEqual(aicheck.score(None), -1)
        self.assertEqual(aicheck.summary(None), '')

    def test_names_server_after_place(self):
        from vps2vpn import aicheck
        self.fake(self.US_OK)
        res = aicheck.run()
        cli.quick_setup(res)
        self.assertEqual(db.settings()['node_name'], '西雅图')
        brief = cli.ai_brief(res)
        self.assertEqual(brief['summary'], 'Claude ✓  ChatGPT ✓  Gemini ✓')
        self.assertEqual(brief['kind'], aicheck.KIND_TEXT['hosting'])

    def test_telegram_command(self):
        from vps2vpn import jobs
        self.fake(self.US_OK)
        out = jobs.tg_command('/ai')
        self.assertIn('Claude ✓', out)
        self.assertIn('/ai', jobs.tg_command('/help'))


class AIRouting(tu.Base):
    def test_ai_sites_go_to_ai_group_everywhere(self):
        from vps2vpn import subscription
        uid = db.add_user('erin')
        s, u = db.settings(), db.user(uid)
        c = subscription.clash(s, u, 'https://e.org')
        self.assertIn('DOMAIN-SUFFIX,claude.ai,AI服务', c['rules'])
        self.assertIn('DOMAIN-SUFFIX,anthropic.com,AI服务', c['rules'])
        sb = subscription.singbox(s, u, 'https://e.org')
        self.assertIn({'domain_suffix': ['claude.ai'], 'outbound': 'AI服务'}, sb['route']['rules'])
        sr = subscription.shadowrocket(s, u, 'https://e.org')
        self.assertIn('DOMAIN-SUFFIX,claude.ai,AI服务', sr)
        # turned off: no AI group, no AI lines
        c = subscription.clash(dict(s, ai_group=False), u, 'https://e.org')
        self.assertFalse(any('AI服务' in r for r in c['rules']))

    def test_best_ai_server_first(self):
        from vps2vpn import subscription
        ns = [{'group': 'Sydney', 'ai_score': 3}, {'group': 'HK', 'ai_score': 0}, {'group': 'Tokyo', 'ai_score': 4},
              {'group': 'Seattle', 'ai_score': 4}]
        per = [('Sydney', []), ('HK', []), ('Tokyo', []), ('Seattle', [])]
        self.assertEqual(subscription.ai_servers(ns, per), ['Tokyo', 'Seattle', 'Sydney', 'HK'])


class ServerNames(tu.Base):
    def test_same_city_gets_a_number(self):
        db.set_settings(node_name='悉尼', servers=[{'id': 'a1', 'name': '悉尼 2'}, {'id': 'b2', 'name': '东京'}])
        s = db.settings()
        self.assertEqual(cluster.unique_name('悉尼', s), '悉尼 3')
        self.assertEqual(cluster.unique_name('东京', s), '东京 2')
        self.assertEqual(cluster.unique_name('东京', s, skip='b2'), '东京')      # renaming a server to its own name
        self.assertEqual(cluster.unique_name('首尔', s), '首尔')


class DeploySecurity(unittest.TestCase):
    def test_safe_url_blocks_unsafe_and_allows_valid(self):
        for bad in ('javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'file:///etc/passwd',
                    'file:///C:/Windows/System32/calc.exe', r'\\evil\share\x.exe',
                    '-flag', '--option=https://example.com', 'https://example.com\nfoo', ''):
            self.assertEqual(deploy.safe_url(bad), '', bad)
        self.assertTrue(deploy.safe_url('clash://install-config?url=https%3A%2F%2Fexample.com%2Fs%2Ftok'))
        self.assertTrue(deploy.safe_url('https://example.com/path?x=1'))
        self.assertEqual(deploy.safe_url('http://example.com/', ('https',)), '')
        with self.assertRaises(ValueError):
            deploy.open_link('file:///etc/passwd')

    def test_new_job_validates_port_and_host(self):
        self.assertIsNone(deploy.new_job('-oProxyCommand=id', 'root', '22')[0])
        self.assertIsNone(deploy.new_job('203.0.113.10', 'root', '0')[0])
        self.assertIsNone(deploy.new_job('203.0.113.10', 'root', '70000')[0])
        job, err = deploy.new_job('203.0.113.10', 'root', '2222')
        self.assertEqual((job['port'], err), (2222, ''))

    def test_recheck_requires_passing_panel_check(self):
        opened = []
        orig = deploy.open_link
        deploy.open_link = lambda u, schemes=deploy.LINK_SCHEMES: opened.append(u)
        try:
            job = {'host': '127.0.0.1', 'rec': {'checks': [], 'links': {'clash': 'clash://x'}},
                   'client': {'name': 'Clash Verge', 'link': 'clash'}}
            deploy.recheck(job)
            self.assertEqual(opened, [])
        finally:
            deploy.open_link = orig


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_SH = os.path.join(ROOT_DIR, 'install.sh')
# Windows' own bash.exe is WSL, not a POSIX shell for this checkout: there, set V2V_TEST_BASH to Git's bash.
TEST_BASH = os.environ.get('V2V_TEST_BASH') or (shutil.which('bash') if os.name != 'nt' else None)

CURL_STUB = r"""#!/bin/bash
# offline curl: serves $FIX/api.json for GitHub's API and $FIX/files/<basename of the URL> for downloads
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H|--connect-timeout|--max-time|--retry) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$FIX/curl.log"
case "$url" in
  https://api.github.com/*) f="$FIX/api.json" ;;
  *) f="$FIX/files/${url##*/}" ;;
esac
[ -f "$f" ] || exit 22
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
"""


def _posix(path):
    """A path bash understands. Git bash on Windows: C:\\x -> /c/x (a drive colon breaks PATH and GNU tar)."""
    path = path.replace('\\', '/')
    if os.name == 'nt' and re.match(r'^[A-Za-z]:/', path):
        path = '/' + path[0].lower() + path[2:]
    return path


def _code_tarball(version, prefix):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        data = ("VERSION = '%s'\n" % version).encode()
        info = tarfile.TarInfo(prefix + '/vps2vpn/__init__.py')
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
class Installer(unittest.TestCase):
    """install.sh: verified release by default, explicit unverified dev refs, snapshot + rollback."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fix = os.path.join(self.tmp, 'fix')
        self.files = os.path.join(self.fix, 'files')
        self.root = os.path.join(self.tmp, 'root')
        self.stubs = os.path.join(self.tmp, 'stubs')
        for d in (self.files, self.root, self.stubs):
            os.makedirs(d)
        stub = {'curl': CURL_STUB,
                'python3': '#!/bin/sh\nexec "%s" "$@"\n' % _posix(sys.executable),
                'id': '#!/bin/sh\necho 0\n',
                'chown': '#!/bin/sh\nexit 0\n',
                'systemctl': '#!/bin/sh\necho "$*" >> "$FIX/systemctl.log"\n'}
        for name, body in stub.items():
            with open(os.path.join(self.stubs, name), 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            os.chmod(os.path.join(self.stubs, name), 0o755)
        with open(INSTALL_SH, encoding='utf-8') as f:
            self.pinned = re.search(r'^PINNED_TAG="([^"]+)"', f.read(), re.M).group(1)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, body, **env):
        script = ('export PATH="$STUBS:$PATH"\nsource "$INSTALL"\n'
                  'LIB="$ROOTDIR/lib"; VAR="$ROOTDIR/var"; SNAPS="$VAR/upgrade-snapshots"\n' + body)
        e = dict(os.environ, FIX=_posix(self.fix), STUBS=_posix(self.stubs), INSTALL=_posix(INSTALL_SH),
                 ROOTDIR=_posix(self.root))
        for k in ('V2V_REF', 'V2V_BRANCH', 'V2V_ALLOW_DOWNGRADE'):
            e.pop(k, None)
        e.update(env)
        p = subprocess.run([TEST_BASH, '-c', script], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=120)
        return p.returncode, p.stdout.decode('utf-8', 'replace')

    def put(self, name, data):
        with open(os.path.join(self.files, name), 'wb') as f:
            f.write(data)

    def release(self, tag, version, good=True):
        data = _code_tarball(version, 'vps2vpn-' + tag)
        name = 'vps2vpn-%s.tar.gz' % tag
        self.put(name, data)
        digest = hashlib.sha256(data if good else b'other').hexdigest()
        self.put(name + '.sha256', ('%s  %s\n' % (digest, name)).encode())

    def api(self, tag):
        with open(os.path.join(self.fix, 'api.json'), 'w') as f:
            json.dump({'tag_name': tag}, f)

    FETCH = 'rm -rf "$ROOTDIR/t"; mkdir -p "$ROOTDIR/t" && fetch_panel_code "$ROOTDIR/t" && cat "$ROOTDIR/t/vps2vpn/__init__.py"'

    def urls(self):
        with open(os.path.join(self.fix, 'curl.log')) as f:
            return f.read().split()

    def test_latest_release_is_verified(self):
        self.api('v9.9.9')
        self.release('v9.9.9', '9.9.9')
        rc, out = self.sh(self.FETCH)
        self.assertEqual(rc, 0, out)
        self.assertIn("VERSION = '9.9.9'", out)
        self.assertIn('checksum OK', out)
        self.assertNotIn('UNVERIFIED', out)
        self.assertIn('https://github.com/xydadada/vps2vpn/releases/download/v9.9.9/vps2vpn-v9.9.9.tar.gz.sha256',
                      self.urls())

    def test_checksum_mismatch_or_missing_is_refused(self):
        self.api('v9.9.9')
        self.release('v9.9.9', '9.9.9', good=False)
        self.put('v9.9.9.tar.gz', _code_tarball('9.9.9', 'x'))          # must not be used as a way around
        rc, out = self.sh(self.FETCH)
        self.assertNotEqual(rc, 0)
        self.assertIn('checksum mismatch', out)
        self.assertFalse(os.path.exists(os.path.join(self.root, 't', 'vps2vpn')))     # never unpacked
        os.unlink(os.path.join(self.files, 'vps2vpn-v9.9.9.tar.gz.sha256'))
        rc, out = self.sh(self.FETCH)
        self.assertNotEqual(rc, 0)
        self.assertIn('download failed', out)
        self.assertFalse(os.path.exists(os.path.join(self.root, 't', 'vps2vpn')))

    def test_release_without_tarball_uses_the_tag_archive(self):
        # releases made before the release workflow (e.g. v0.2.5) have no vps2vpn-<tag>.tar.gz
        self.api('v9.9.9')
        self.put('v9.9.9.tar.gz', _code_tarball('9.9.9', 'vps2vpn-9.9.9'))
        self.put('main.tar.gz', _code_tarball('0.0.1', 'vps2vpn-main'))
        rc, out = self.sh(self.FETCH)
        self.assertEqual(rc, 0, out)
        self.assertIn("VERSION = '9.9.9'", out)
        self.assertIn('UNVERIFIED', out)
        self.assertIn('https://github.com/xydadada/vps2vpn/archive/refs/tags/v9.9.9.tar.gz', self.urls())

    def test_api_unreachable_uses_pinned_tag_then_main(self):
        self.release(self.pinned, self.pinned[1:])
        rc, out = self.sh(self.FETCH)
        self.assertEqual(rc, 0, out)
        self.assertIn('pinned release ' + self.pinned, out)
        self.assertIn('checksum OK', out)
        # nothing published at all: the old behaviour (main), loudly unverified
        shutil.rmtree(self.files)
        os.makedirs(self.files)
        self.put('main.tar.gz', _code_tarball('0.0.1', 'vps2vpn-main'))
        rc, out = self.sh(self.FETCH)
        self.assertEqual(rc, 0, out)
        self.assertIn("VERSION = '0.0.1'", out)
        self.assertIn('installing the main branch, UNVERIFIED', out)

    def test_dev_ref_is_explicit_and_unverified(self):
        self.api('v9.9.9')
        self.release('v9.9.9', '9.9.9')
        self.put('dev.tar.gz', _code_tarball('9.9.10', 'vps2vpn-dev'))
        rc, out = self.sh(self.FETCH, V2V_REF='dev')
        self.assertEqual(rc, 0, out)
        self.assertIn("VERSION = '9.9.10'", out)
        self.assertIn('UNVERIFIED development install', out)
        self.assertEqual(self.urls(), ['https://github.com/xydadada/vps2vpn/archive/dev.tar.gz'])
        rc, out = self.sh(self.FETCH, V2V_REF='-o /etc/passwd')
        self.assertNotEqual(rc, 0)
        self.assertIn('not a branch', out)

    def test_release_older_than_install_is_not_a_silent_downgrade(self):
        os.makedirs(os.path.join(self.root, 'lib', 'app', 'vps2vpn'))
        with open(os.path.join(self.root, 'lib', 'app', 'vps2vpn', '__init__.py'), 'w') as f:
            f.write("VERSION = '9.10.0'\n")
        self.api('v9.9.9')
        self.release('v9.9.9', '9.9.9')
        rc, out = self.sh(self.FETCH)
        self.assertNotEqual(rc, 0)
        self.assertIn('not downgrading', out)
        rc, out = self.sh(self.FETCH, V2V_ALLOW_DOWNGRADE='1')
        self.assertEqual(rc, 0, out)

    def test_snapshot_keeps_three_and_restores(self):
        app = os.path.join(self.root, 'lib', 'app', 'vps2vpn')
        var = os.path.join(self.root, 'var')
        snaps = os.path.join(var, 'upgrade-snapshots')
        os.makedirs(app)
        with open(os.path.join(app, '__init__.py'), 'w') as f:
            f.write("VERSION = '1.0.0'\n")
        for old in ('20200101-000000-v0.1', '20200102-000000-v0.2', '20200103-000000-v0.3'):
            os.makedirs(os.path.join(snaps, old))
        dbf = os.path.join(var, 'vps2vpn.db')
        live = sqlite3.connect(dbf, isolation_level=None)
        live.execute('PRAGMA journal_mode=WAL')
        live.execute('PRAGMA wal_autocheckpoint=0')        # the row stays in the -wal file: a plain cp would miss it
        live.execute('CREATE TABLE t (v TEXT)')
        live.execute("INSERT INTO t VALUES ('before')")
        rc, out = self.sh('snapshot_before_upgrade; echo "SNAP=$SNAPSHOT"')
        live.close()
        self.assertEqual(rc, 0, out)
        self.assertIn('to roll back this upgrade later:  sudo bash ', out)
        kept = sorted(os.listdir(snaps))
        self.assertEqual(len(kept), 3, kept)
        self.assertNotIn('20200101-000000-v0.1', kept)
        new = kept[-1]
        self.assertTrue(new.endswith('-v1.0.0'), new)
        if os.name != 'nt':
            self.assertEqual(os.stat(os.path.join(snaps, new)).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(os.path.join(snaps, new, 'vps2vpn.db')).st_mode & 0o077, 0)
        snap = sqlite3.connect(os.path.join(snaps, new, 'vps2vpn.db'))
        self.assertEqual(snap.execute('SELECT v FROM t').fetchall(), [('before',)])
        snap.close()

        # the upgrade changes code and data; restore.sh puts both back
        with open(os.path.join(app, '__init__.py'), 'w') as f:
            f.write("VERSION = '2.0.0'\n")
        c = sqlite3.connect(dbf, isolation_level=None)
        c.execute("INSERT INTO t VALUES ('after')")
        c.close()
        rc, out = self.sh('bash "$SNAPS/%s/restore.sh"' % new)
        self.assertEqual(rc, 0, out)
        c = sqlite3.connect(dbf)
        self.assertEqual(c.execute('SELECT v FROM t').fetchall(), [('before',)])
        c.close()
        with open(os.path.join(app, '__init__.py')) as f:
            self.assertEqual(f.read(), "VERSION = '1.0.0'\n")
        with open(os.path.join(self.fix, 'systemctl.log')) as f:
            self.assertEqual(f.read().split(), ['stop', 'vps2vpn', 'start', 'vps2vpn'])

    def stub(self, name, body):
        path = os.path.join(self.stubs, name)
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('#!/bin/sh\n' + body)
        os.chmod(path, 0o755)

    def test_apt_waits_for_the_dpkg_lock_and_never_prompts(self):
        # a fresh Ubuntu VPS runs unattended-upgrades at first boot; needrestart asks which services to restart
        self.stub('apt-get', 'echo "DF=$DEBIAN_FRONTEND NR=$NEEDRESTART_SUSPEND $*" >> "$FIX/apt.log"\n')
        rc, out = self.sh('PATH="$STUBS"; install_packages; echo "PY=$PY"')
        self.assertEqual(rc, 0, out)
        self.assertIn('PY=' + _posix(os.path.join(self.stubs, 'python3')), out)
        with open(os.path.join(self.fix, 'apt.log')) as f:
            calls = f.read().splitlines()
        self.assertEqual(len(calls), 2, calls)
        for c in calls:
            self.assertIn('DF=noninteractive NR=1 ', c)
            self.assertIn('-o DPkg::Lock::Timeout=300', c)
            self.assertIn('-o Dpkg::Options::=--force-confold', c)
        self.assertIn(' update ', calls[0] + ' ')
        self.assertIn(' install -y ', calls[1])
        self.assertTrue(calls[1].endswith(' findutils passwd kmod procps iproute2'), calls[1])  # minimal images

    def test_end_of_life_debian_11_falls_back_to_archive_debian_org(self):
        # bullseye's security updates left deb.debian.org: installing anything updated there fails with 404
        osr = os.path.join(self.tmp, 'os-release')
        with open(osr, 'w') as f:
            f.write('ID=debian\nVERSION_ID="11"\nVERSION_CODENAME=bullseye\n')
        src = os.path.join(self.tmp, 'sources.list.d')
        os.makedirs(src)
        self.stub('apt-get', 'echo "$*" >> "$FIX/apt.log"\n'
                             'case "$*" in *" install "*) [ -f "$SRC/vps2vpn-debian-archive.list" ] || exit 100 ;; esac\n')
        body = 'PATH="$STUBS"; OS_RELEASE="%s"; APT_SOURCES="$SRC"; install_packages' % _posix(osr)
        rc, out = self.sh(body, SRC=_posix(src))
        self.assertEqual(rc, 0, out)
        self.assertIn('archive.debian.org', out)
        with open(os.path.join(src, 'vps2vpn-debian-archive.list')) as f:
            self.assertEqual(f.read().splitlines(), [
                'deb [check-valid-until=no] http://archive.debian.org/debian bullseye main',
                'deb [check-valid-until=no] http://archive.debian.org/debian bullseye-updates main',
                'deb [check-valid-until=no] http://archive.debian.org/debian-security bullseye-security main'])
        with open(os.path.join(self.fix, 'apt.log')) as f:
            self.assertEqual([re.search(r' (update|install) ', c).group(1) for c in f.read().splitlines()],
                             ['update', 'install', 'update', 'install'])
        # any other release, or a second failure, is a plain error: never touch the sources of a supported one
        os.unlink(os.path.join(src, 'vps2vpn-debian-archive.list'))
        with open(osr, 'w') as f:
            f.write('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        rc, out = self.sh(body, SRC=_posix(src))
        self.assertNotEqual(rc, 0)
        self.assertIn('could not install the system packages', out)
        self.assertEqual(os.listdir(src), [])

    def test_install_lock_keeps_error_messages_visible(self):
        # "exec 9>lock 2>/dev/null" once sent every later error (die) of the installer to /dev/null
        self.stub('flock', 'exit 0\n')
        rc, out = self.sh('LOCK="$ROOTDIR/install.lock"; one_at_a_time; die "still visible"')
        self.assertNotEqual(rc, 0)
        self.assertIn('error:', out)
        self.assertIn('still visible', out)

    def test_python_older_than_3_8_gets_a_newer_one_next_to_it(self):
        # RHEL/Rocky/Alma 8 and openSUSE Leap 15: python3 is 3.6
        self.stub('python3', 'if [ "$1" = --version ]; then echo "Python 3.6.8"; exit 0; fi\nexit 1\n')
        self.stub('python3.12', '[ -f "$FIX/has-python3.12" ] || exit 127\nexec "%s" "$@"\n' % _posix(sys.executable))
        self.stub('dnf', 'echo "$*" >> "$FIX/dnf.log"\n'
                         'case "$*" in *python3.12*) : > "$FIX/has-python3.12" ;; esac\n')
        rc, out = self.sh('PATH="$STUBS"; install_packages; echo "PY=$PY"')
        self.assertEqual(rc, 0, out)
        self.assertIn('Python 3.6.8 is too old', out)
        self.assertIn('PY=' + _posix(os.path.join(self.stubs, 'python3.12')), out)
        with open(os.path.join(self.fix, 'dnf.log')) as f:
            self.assertEqual(f.read().splitlines()[-1], 'install -y -q python3.12')
        # no newer Python to be had: a clear error instead of a panel that cannot start
        self.stub('dnf', 'case "$*" in *python3.1*|*python39*|*python31*) exit 1 ;; esac\n')
        os.unlink(os.path.join(self.fix, 'has-python3.12'))
        rc, out = self.sh('PATH="$STUBS"; install_packages; echo "PY=$PY"')
        self.assertNotEqual(rc, 0)
        self.assertIn('python 3.8 or newer is required (found: Python 3.6.8)', out)
        # a package manager that fails says so, instead of set -e stopping the installer without a word
        self.stub('dnf', 'exit 1\n')
        rc, out = self.sh('PATH="$STUBS"; install_packages')
        self.assertNotEqual(rc, 0)
        self.assertIn('could not install the system packages', out)

    def test_services_and_commands_run_the_chosen_python(self):
        with open(INSTALL_SH, encoding='utf-8') as f:
            sh = f.read()
        self.assertIn('ExecStart=$PY -m vps2vpn serve', sh)
        self.assertIn('exec $PY -m vps2vpn', sh)                       # /usr/local/bin/vps2vpn
        self.assertNotRegex(sh, r'(?m)^[^#\n]*(?<![.\w])python3 -[cm] ')  # every call goes through $PY

    def test_units_use_newer_hardening_only_where_systemd_knows_it(self):
        # EL8 has systemd 239: ProtectClock (245) / ProtectKernelLogs (244) would be logged as unknown lvalues
        for version, want in (('239 (239-78.el8)', ''), ('252 (252.39-1~deb12u2)', 'ProtectClock=yes\nProtectKernelLogs=yes')):
            self.stub('systemctl', 'echo "systemd %s"; echo "+PAM +AUDIT"\n' % version)
            rc, out = self.sh('printf "[%s]" "$(systemd_new_hardening)"')
            self.assertEqual(rc, 0, out)
            self.assertEqual(out, '[%s]' % want)
        self.stub('systemctl', 'exit 1\n')
        rc, out = self.sh('printf "[%s]" "$(systemd_new_hardening)"')
        self.assertEqual((rc, out), (0, '[]'))
        with open(INSTALL_SH, encoding='utf-8') as f:
            self.assertEqual(f.read().count('\n$NEW_HARDENING\n'), 4)       # all four units

    def test_ipv6_only_download_failure_says_why(self):
        routes = os.path.join(self.tmp, 'route')
        with open(routes, 'w') as f:
            f.write('Iface\tDestination\tGateway\n')                   # IPv6-only: no IPv4 routes at all
        body = 'ROUTE4="%s"; fetch https://github.com/x/y/archive/none.tar.gz "$ROOTDIR/out"' % _posix(routes)
        rc, out = self.sh(body)
        self.assertNotEqual(rc, 0)
        self.assertIn('download failed', out)
        self.assertIn('no IPv4', out)
        with open(routes, 'a') as f:
            f.write('eth0\t00000000\t0102A8C0\n')
        rc, out = self.sh(body)
        self.assertNotEqual(rc, 0)
        self.assertIn('download failed', out)
        self.assertNotIn('no IPv4', out)

    def test_fresh_install_makes_no_snapshot(self):
        rc, out = self.sh('snapshot_before_upgrade; echo "SNAP=[$SNAPSHOT]"')
        self.assertEqual(rc, 0, out)
        self.assertIn('SNAP=[]', out)


class MissingSystemTools(unittest.TestCase):
    """Minimal images (containers, some VPS templates) lack modprobe, sysctl or ss: `vps2vpn init` used to
    crash with FileNotFoundError at modprobe, so the install failed after everything was downloaded."""

    def setUp(self):
        from vps2vpn import paths, system
        self.paths, self.system = paths, system
        self._live = paths.LIVE
        paths.LIVE = True

    def tearDown(self):
        self.paths.LIVE = self._live

    def test_a_missing_tool_is_a_failed_command(self):
        r = self.system.run(['vps2vpn-no-such-tool', '-x'])
        self.assertEqual(r.returncode, 127)
        self.assertIn('vps2vpn-no-such-tool', r.stderr)
        with self.assertRaises(RuntimeError):
            self.system.run(['vps2vpn-no-such-tool'], check=True)

    def test_tune_network_survives_without_modprobe_and_sysctl(self):
        tmp = tempfile.mkdtemp()
        old = self.paths.SYSCTL_FILE, self.paths.MODULES_FILE, self.system.run
        self.paths.SYSCTL_FILE = os.path.join(tmp, 'sysctl.conf')
        self.paths.MODULES_FILE = os.path.join(tmp, 'modules.conf')
        real = self.system.run
        self.system.run = lambda cmd, **kw: real(['vps2vpn-no-such-' + cmd[0]] + cmd[1:], **kw)
        try:
            self.assertTrue(self.system.tune_network(True).startswith('partial: '))
            self.assertTrue(os.path.exists(self.paths.SYSCTL_FILE))       # applied at the next boot
        finally:
            self.paths.SYSCTL_FILE, self.paths.MODULES_FILE, self.system.run = old
            shutil.rmtree(tmp, ignore_errors=True)


class ReleaseWorkflow(unittest.TestCase):
    def test_release_workflow_is_minimal_and_reproducible(self):
        with open(os.path.join(ROOT_DIR, '.github', 'workflows', 'release.yml'), encoding='utf-8') as f:
            wf = f.read()
        self.assertIn("tags: ['v*']", wf)
        self.assertRegex(wf, r'(?m)^permissions:\n  contents: read$')            # nothing more by default
        self.assertEqual(wf.count('contents: write'), 1)
        self.assertEqual(set(re.findall(r'uses: (\S+)', wf)), {'actions/checkout@v4'})
        self.assertIn('git archive --format=tar --prefix="vps2vpn-$TAG/" HEAD | gzip -n -9', wf)
        self.assertIn('sha256sum "$name" > "$name.sha256"', wf)
        with open(INSTALL_SH, encoding='utf-8') as f:
            sh = f.read()
        self.assertIn('releases/download/$tag/$name.sha256', sh)
        self.assertNotIn('archive/refs/heads/$BRANCH', sh)            # the tip of main is no longer the default


# A records folder like "C:\Users\John Smith\vps2vpn": ssh splits UserKnownHostsFile on spaces (a list of files)
# and expands %-tokens and a leading ~ in each file, so this name shows both a split and a missing %% at once.
ODD_DIR = 'v2v ~/50%c'

PS_HARNESS = r'''param([string]$Ps1, [string]$Echo)
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Ps1, [ref]$null, [ref]$errs)
if ($errs.Count) { throw "deploy.ps1 does not parse: $($errs[0].Message)" }
$want = 'Restrict-Path', 'Quote-Arg', 'Get-KnownHostsFile', 'Get-KnownHostName', 'Get-SshArgs', 'Explain'
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($want -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$Records = $env:V2V_RECORDS; $Server = '203.0.113.10'; $User = 'root'; $Port = 2222
# the same command line Start-Ssh hands to ssh.exe, read back by a program with the same argv rules
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $env:V2V_PY; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
$psi.Arguments = (Quote-Arg $Echo) + ' ' + ((Get-SshArgs $null $false) -join ' ')
$p = [Diagnostics.Process]::Start($psi); $argv = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
[Console]::Out.WriteLine($argv.Trim())
[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Explain 'Host key verification failed.'))))
'''


class DeployerKnownHosts(unittest.TestCase):
    """The server's SSH key is remembered between runs (a changed key is refused, not trusted again), in a file
    path ssh reads as one file; the local page's token check never crashes on odd input."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.records = os.path.join(self.tmp, *ODD_DIR.split('/'))
        self.kh = os.path.join(self.records, 'known_hosts')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_python_deployer_passes_one_quoted_file(self):
        old = deploy.RECORDS
        deploy.RECORDS = self.records
        try:
            cmd, _ = deploy.ssh_base({'host': '203.0.113.10', 'user': 'root', 'port': 2222, 'key': '/k'})
        finally:
            deploy.RECORDS = old
        self.assertTrue(os.path.isdir(self.records))
        opt = 'UserKnownHostsFile="%s"' % self.kh.replace('%', '%%')
        self.assertIn(opt, cmd)
        self.assertEqual(deploy.known_host_name('203.0.113.10', 22), '203.0.113.10')
        self.assertEqual(deploy.known_host_name('2001:db8::1', 2222), '[2001:db8::1]:2222')
        ssh = shutil.which('ssh')
        if ssh:         # ssh itself reads it back as the one file, unchanged
            r = subprocess.run([ssh, '-G', '-F', 'none', '-o', opt, 'h'], capture_output=True, timeout=30,
                               stdin=subprocess.DEVNULL)
            lines = [ln for ln in r.stdout.decode('utf-8', 'replace').splitlines()
                     if ln.startswith('userknownhostsfile ')]
            self.assertEqual(lines, ['userknownhostsfile ' + self.kh], r.stderr)

    def test_token_check_takes_non_ascii(self):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), deploy.H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def get(q):
                c = http.client.HTTPConnection('127.0.0.1', srv.server_address[1], timeout=10)
                try:
                    c.request('GET', '/records?t=' + q)
                    return c.getresponse().status
                finally:
                    c.close()
            self.assertEqual(get('%E4%B8%AD%E6%96%87'), 404)        # was a TypeError and a dropped connection
            self.assertEqual(get('%ff'), 404)
            self.assertEqual(get(deploy.TOKEN), 200)
        finally:
            srv.shutdown()
            srv.server_close()

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'needs Windows PowerShell')
    def test_windows_deployer_keeps_the_quotes_to_ssh(self):
        with open(os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1'), 'rb') as f:
            self.assertEqual(f.read(3), b'\xef\xbb\xbf')          # PowerShell 5 reads it as UTF-8 only with the BOM
        harness = os.path.join(self.tmp, 'harness.ps1')
        echo = os.path.join(self.tmp, 'echo.py')
        with open(harness, 'w', encoding='utf-8-sig') as f:
            f.write(PS_HARNESS)
        with open(echo, 'w', encoding='utf-8') as f:
            f.write('import json, sys\nprint(json.dumps(sys.argv[1:]))\n')
        p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness,
                            '-Ps1', os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1'), '-Echo', echo],
                           env=dict(os.environ, V2V_RECORDS=self.records, V2V_PY=sys.executable),
                           capture_output=True, timeout=120)
        out = p.stdout.decode('utf-8', 'replace').strip().splitlines()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        argv = json.loads(out[0])
        self.assertEqual(argv[argv.index('StrictHostKeyChecking=accept-new') + 2],
                         'UserKnownHostsFile="%s"' % self.kh.replace('%', '%%'))
        self.assertTrue(os.path.isdir(self.records))         # next to the saved logins, not in the temp folder
        hint = base64.b64decode(out[1]).decode('utf-8')
        self.assertIn('ssh-keygen -R [203.0.113.10]:2222 -f "%s"' % self.kh, hint)

    @unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
    def test_mac_deployer_remembers_the_key_in_home(self):
        stubs, fix, home = (os.path.join(self.tmp, d) for d in ('stubs', 'fix', 'h o%c'))
        for d in (stubs, fix, home):
            os.makedirs(d)
        for name, body in {'ssh': '#!/bin/sh\nfor a; do printf "%s\\n" "$a"; done > "$FIX/ssh.args"\n'
                                  'cat >/dev/null\nexit 255\n',
                           'python3': '#!/bin/sh\nexit 1\n'}.items():         # no Python: the bash path runs
            with open(os.path.join(stubs, name), 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            os.chmod(os.path.join(stubs, name), 0o755)
        env = dict(os.environ, HOME=_posix(home), FIX=_posix(fix), STUBS=_posix(stubs))
        p = subprocess.run([TEST_BASH, '-c', 'export PATH="$STUBS:$PATH"; exec bash "$1"', 'x',
                            _posix(os.path.join(ROOT_DIR, 'deploy-mac.command'))],
                           input=b'203.0.113.10\n\n\n2222\n', env=env, capture_output=True, timeout=120)
        out = (p.stdout + p.stderr).decode('utf-8', 'replace')
        self.assertEqual(p.returncode, 1, out)
        with open(os.path.join(fix, 'ssh.args'), encoding='utf-8') as f:
            args = f.read().splitlines()
        kh = _posix(home) + '/vps2vpn/known_hosts'
        self.assertIn('UserKnownHostsFile="%s"' % kh.replace('%', '%%'), args)
        self.assertTrue(os.path.isdir(os.path.join(home, 'vps2vpn')))
        self.assertIn("ssh-keygen -R '[203.0.113.10]:2222' -f '%s'" % kh, out)


# --- key files, cloud login users and the installer code source (no server needed) ---

DEPLOY_PS1 = os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1')
AWS_ROOT = 'Please login as the user "ubuntu" rather than the user "root".\n\n'


def openssh_key(cipher):
    """A minimal new-format OpenSSH private key blob: only the header matters to the check."""
    def s(b):
        return len(b).to_bytes(4, 'big') + b
    raw = b'openssh-key-v1\x00' + s(cipher) + s(b'none' if cipher == b'none' else b'bcrypt') + s(b'') + b'\x00' * 8
    body = base64.b64encode(raw).decode()
    return '-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n' % body


KEYS = {
    'ok_openssh': (openssh_key(b'none'), ''),
    'ok_openssh_crlf': (openssh_key(b'none').replace('\n', '\r\n'), ''),
    'ok_pem': ('-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n', ''),
    'ppk': ('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n', 'PuTTY'),
    'pub': ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me@pc\n', '公钥'),
    'junk': ('hello\n', 'PRIVATE KEY'),
    'enc_openssh': (openssh_key(b'aes256-ctr'), '密码保护'),
    'enc_pem': ('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nMIIE==\n'
                '-----END RSA PRIVATE KEY-----\n', '密码保护'),
}


class KeyChecks(unittest.TestCase):
    def test_key_problem(self):
        for name, (text, want) in KEYS.items():
            with self.subTest(name):
                got = deploy.key_problem(text)
                if want:
                    self.assertIn(want, got)
                else:
                    self.assertEqual(got, '')

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'needs ssh-keygen')
    def test_real_keys(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for pw, bad in (('', False), ('secret-pass', True)):
            path = os.path.join(d, 'k%d' % bad)
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', pw, '-f', path], check=True,
                           capture_output=True)
            with open(path) as f:
                self.assertEqual(bool(deploy.key_problem(f.read())), bad)

    def test_login_as_hint(self):
        self.assertEqual(deploy.login_as_hint(AWS_ROOT), 'ubuntu')
        self.assertEqual(deploy.login_as_hint('Please login as the user "ec2-user" rather than the user "root".'),
                         'ec2-user')
        self.assertEqual(deploy.login_as_hint('Permission denied (publickey).'), '')
        self.assertEqual(deploy.login_as_hint('login as the user "x; rm -rf /" rather than'), '')

    def test_start_refuses_unusable_key(self):
        """The local page gets a clear 400 instead of a job that fails later with an ssh error."""
        sent = {}
        h = deploy.H.__new__(deploy.H)
        body = json.dumps({'host': '203.0.113.10', 'key': KEYS['ppk'][0]}).encode()
        h.headers = {'Content-Length': str(len(body))}
        h.rfile = io.BytesIO(body)
        h.path = '/start?t=' + deploy.TOKEN
        h.reply = lambda code, text, *a, **k: sent.update(code=code, text=text)
        with mock.patch.object(deploy.threading, 'Thread') as th:
            h.do_POST()
        self.assertEqual(sent['code'], 400, sent)
        self.assertIn('PuTTY', json.loads(sent['text'])['error'])
        th.assert_not_called()


class LoginAsRetry(unittest.TestCase):
    """AWS images answer a root login with 'Please login as the user "ubuntu"': try that user once by itself."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self._old = deploy.RECORDS
        deploy.RECORDS = self.dir
        self.addCleanup(setattr, deploy, 'RECORDS', self._old)

    def run_with(self, answers):
        calls = []

        def fake_probe(cmd, env, user):
            calls.append((cmd[-1], user))
            out, rc = answers[len(calls) - 1]
            return subprocess.CompletedProcess(cmd, rc, out, '')
        job, err = deploy.new_job('203.0.113.10', 'root', '22')
        self.assertFalse(err)
        job['key'] = os.path.join(self.dir, 'key')
        job['no_import'] = True
        with mock.patch.object(deploy, 'probe', fake_probe), \
                mock.patch.object(deploy.shutil, 'which', return_value='ssh'):
            deploy.run_job(job)
        return job, calls

    def test_retries_with_the_user_the_server_names(self):
        job, calls = self.run_with([(AWS_ROOT, 142), ('', 255)])
        self.assertEqual(calls, [('root@203.0.113.10', 'root'), ('ubuntu@203.0.113.10', 'ubuntu')])
        self.assertEqual(job['user'], 'ubuntu')
        self.assertEqual(job['state'], 'error')

    def test_no_retry_for_other_errors(self):
        job, calls = self.run_with([('Permission denied (publickey).', 255)])
        self.assertEqual(len(calls), 1)
        self.assertEqual(job['user'], 'root')
        self.assertIn('ubuntu / ec2-user', job['error'])


PS_KEY_HARNESS = r'''param([string]$Ps1, [string]$Dir)
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Ps1, [ref]$null, [ref]$errs)
if ($errs.Count) { throw "deploy.ps1 does not parse: $($errs[0].Message)" }
$want = 'Get-KeyProblem', 'Get-LoginAsUser', 'Explain'
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($want -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$User = 'root'; $Port = 22; $Server = '203.0.113.10'; $Records = $Dir
$out = [ordered]@{}
foreach ($k in Get-ChildItem -LiteralPath $Dir -Filter '*.key') {
  $out[$k.BaseName] = Get-KeyProblem (([IO.File]::ReadAllText($k.FullName)) -replace "`r`n", "`n")
}
$out['_login'] = Get-LoginAsUser 'Please login as the user "ubuntu" rather than the user "root".'
$out['_explain'] = Explain 'Please login as the user "ubuntu" rather than the user "root".'
[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Compress))))
'''


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'needs Windows PowerShell')
class PowerShellDeployer(unittest.TestCase):
    """deploy.ps1 gives the same answers as deploy.py for the same key files."""

    def test_same_key_checks(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, (text, _) in KEYS.items():
            with open(os.path.join(d, name + '.key'), 'w', encoding='utf-8', newline='') as f:
                f.write(text)
        harness = os.path.join(d, 'harness.ps1')
        with open(harness, 'w', encoding='utf-8-sig') as f:
            f.write(PS_KEY_HARNESS)
        p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness,
                            '-Ps1', DEPLOY_PS1, '-Dir', d], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(base64.b64decode(p.stdout.strip().splitlines()[-1]).decode('utf-8'))
        for name, (text, want) in KEYS.items():
            with self.subTest(name):
                self.assertEqual(got[name] or '', deploy.key_problem(text))
        self.assertEqual(got['_login'], 'ubuntu')
        self.assertIn('把用户名改成 ubuntu', got['_explain'])

    def test_aws_default_user_rule(self):
        with open(DEPLOY_PS1, encoding='utf-8-sig') as f:
            src = f.read()
        self.assertNotIn(r"'Lightsail|\.pem$'", src)     # any .pem used to switch the user to ubuntu


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class InstallerCodeSource(unittest.TestCase):
    """install.sh uses panel code next to itself only when it is a real file, never the current directory of a
    piped install (curl ... | bash), which would replace the verified release download."""

    def setUp(self):
        with open(INSTALL_SH, encoding='utf-8') as f:
            sh = f.read()
        start = sh.index('install_app() {')
        end = sh.index('    fetch_panel_code "$tmp"\n  fi\n', start) + len('    fetch_panel_code "$tmp"\n  fi\n')
        self.snippet = ('set -eu\n_TMPDIRS=()\nsay() { echo "SAY: $*"; }\nfetch_panel_code() { echo FETCH; }\n'
                        + sh[start:end] + '}\ninstall_app\n')
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.makedirs(os.path.join(self.dir, 'vps2vpn'))
        open(os.path.join(self.dir, 'vps2vpn', '__init__.py'), 'w').close()

    def bash(self, args, stdin=None):
        p = subprocess.run(['bash'] + args, input=stdin, cwd=self.dir, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def test_piped_ignores_current_directory(self):
        out = self.bash(['-s'], self.snippet)
        self.assertIn('FETCH', out)
        self.assertNotIn('next to this script', out)

    def test_script_file_uses_code_next_to_it(self):
        with open(os.path.join(self.dir, 'inst.sh'), 'w', newline='\n') as f:
            f.write(self.snippet)
        out = self.bash(['inst.sh'])
        self.assertIn('next to this script', out)
        self.assertNotIn('FETCH', out)


class MacDeployer(unittest.TestCase):
    def test_rules(self):
        with open(os.path.join(ROOT_DIR, 'deploy-mac.command'), encoding='utf-8') as f:
            src = f.read()
        self.assertNotIn('*.pem) USER_DEF=ubuntu', src)
        self.assertIn("tr -d '\\r' < \"$KEY\"", src)                    # CRLF keys from Windows work
        self.assertIn('PuTTY-User-Key-File', src)
        self.assertIn('login as the user', src)



if __name__ == '__main__':
    unittest.main()
