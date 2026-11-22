"""vps2vpn one-click deployer - runs on YOUR computer, installs vps2vpn on your VPS over SSH.

    Windows: double-click deploy-windows.bat      macOS / Linux: python3 deploy/deploy.py

A page opens in your browser. Type the server's IP, drop in the SSH key file you got from your
provider (or type the root password), click Deploy. Everything else is automatic: the installer
creates the admin login and your first account, this tool checks the cloud firewall from the
outside, and (if you choose) adds the new server to one you deployed before. Nothing is installed
on your computer; it only uses the `ssh` program that Windows 10+, macOS and Linux already have.

The admin login of each server is saved only on this computer, in ~/vps2vpn/<server>.json.

Headless (testing):  python3 deploy/deploy.py --headless HOST KEYFILE [USER] [--main MAIN_HOST]
"""
import base64
import glob
import hashlib
import http.client
import http.server
import io
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
WORK = None
TOKEN = secrets.token_urlsafe(16)          # only the browser tab we open can use this local page
RECORDS = os.environ.get('V2V_RECORDS') or os.path.join(os.path.expanduser('~'), 'vps2vpn')
JOBS = {}


def work_dir():
    """Lazily create the temporary work directory on first use (never at import time)."""
    global WORK
    if not WORK or not os.path.isdir(WORK):
        WORK = tempfile.mkdtemp(prefix='vps2vpn-deploy-')
        restrict(WORK)
    return WORK


def package():
    """The panel code and installer, packed for upload."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        tar.add(os.path.join(REPO, 'install.sh'), arcname='install.sh')
        for root, dirs, files in os.walk(os.path.join(REPO, 'vps2vpn')):
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for f in files:
                p = os.path.join(root, f)
                tar.add(p, arcname=os.path.relpath(p, REPO).replace(os.sep, '/'))
    return buf.getvalue()


# --- saved servers (only on this computer) ---------------------------------------------------
def record_path(host):
    return os.path.join(RECORDS, re.sub(r'[^A-Za-z0-9._-]', '_', host) + '.json')


def load_record(host):
    try:
        with open(record_path(host), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def load_records():
    out = []
    for p in sorted(glob.glob(os.path.join(RECORDS, '*.json'))):
        try:
            with open(p, encoding='utf-8') as f:
                d = json.load(f)
            if d.get('host'):
                out.append(d)
        except (OSError, ValueError):
            pass
    return out


LINK_SCHEMES = ('vps2vpn', 'clash', 'hiddify', 'sing-box', 'shadowrocket')
DEFAULT_SAFE_SCHEMES = ('https', 'http') + LINK_SCHEMES


def safe_url(url, schemes=None, host=None):
    """Validate a URL before opening or requesting it."""
    if schemes is None:
        schemes = DEFAULT_SAFE_SCHEMES
    if not isinstance(url, str) or not url or url.startswith('-'):
        return ''
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in url):
        return ''
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return ''
    if u.scheme.lower() not in schemes:
        return ''
    if u.scheme.lower() in ('http', 'https') and not u.hostname:
        return ''
    if host and u.hostname and u.hostname.lower() != host.lower():
        return ''
    return url


def save_record(host, rec):
    os.makedirs(RECORDS, exist_ok=True)
    restrict(RECORDS)
    p = record_path(host)
    fd, tmp = tempfile.mkstemp(dir=RECORDS, prefix='.tmp-')
    try:
        try:
            os.fchmod(fd, 0o600)
        except AttributeError:
            pass
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
        restrict(p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def merge_record(job, res):
    """Remember this server. An upgrade has no new password, so the one saved earlier is kept."""
    a = res.get('auto') or {}
    rec = load_record(job['host'])
    rec.update({k: a[k] for k in ('panel', 'pin', 'join_code', 'name', 'user', 'sub_url', 'qr_url', 'links', 'checks', 'ai')
                if a.get(k) is not None})
    if rec.get('panel'):
        rec['panel'] = safe_url(rec['panel'], ('https',))
    if rec.get('sub_url'):
        rec['sub_url'] = safe_url(rec['sub_url'], ('http', 'https'))
    if rec.get('qr_url'):
        rec['qr_url'] = safe_url(rec['qr_url'], ('http', 'https'))
    if isinstance(rec.get('links'), dict):
        rec['links'] = {k: v for k, v in rec['links'].items() if safe_url(v, LINK_SCHEMES)}
    if a.get('admin_password'):
        rec.update(admin_user=a.get('admin_user', 'admin'), admin_password=a['admin_password'])
    rec.update(host=job['host'], ssh_user=job['user'], ssh_port=job['port'], cloud=res.get('cloud', ''),
               cloud_firewall=res.get('cloud_firewall', ''), updated=time.strftime('%Y-%m-%d %H:%M'),
               说明='vps2vpn 一键部署工具保存的登录信息。只在你自己的电脑上，不要发给别人。')
    return rec


# --- firewall check from the outside ---------------------------------------------------------
def tcp_open(host, port, timeout=5):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def quic_probe(host, port, timeout=3.0):
    """A QUIC packet with an unknown version: Hysteria 2 and TUIC answer with 'version negotiation',
    so an answer proves the UDP port is open all the way through the cloud firewall."""
    pkt = bytes([0xC3]) + b'\x1a\x2a\x3a\x4a' + b'\x08' + os.urandom(8) + b'\x08' + os.urandom(8)
    pkt += b'\x00' * (1200 - len(pkt))
    try:
        infos = socket.getaddrinfo(host, int(port), 0, socket.SOCK_DGRAM)
    except (OSError, ValueError):
        return False
    for fam, socktype, proto, _, addr in infos:
        try:
            with socket.socket(fam, socktype, proto) as s:
                s.settimeout(timeout)
                for _ in range(2):
                    try:
                        s.sendto(pkt, addr)
                        d, _ = s.recvfrom(2048)
                        if len(d) >= 7 and d[0] & 0x80 and d[1:5] == b'\0\0\0\0':
                            return True
                    except socket.timeout:
                        continue
                    except OSError:
                        break
        except OSError:
            continue
    return False


def check_ports(host, checks, tries=3):
    """[{proto, port, name, ok}]. Retries a few times: the services were only just started."""
    out = []
    for c in checks or []:
        if not isinstance(c, (list, tuple)) or len(c) < 3:
            continue
        proto = str(c[0]).lower()
        if proto not in ('tcp', 'udp'):
            continue
        try:
            port = int(c[1])
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        out.append({'proto': proto, 'port': port, 'name': str(c[2]), 'ok': False})
    if not out:
        return out
    for i in range(tries):
        todo = [c for c in out if not c['ok']]
        threads = []
        for c in todo:
            def run(c=c):
                c['ok'] = tcp_open(host, c['port']) if c['proto'] == 'tcp' else quic_probe(host, c['port'])
            t = threading.Thread(target=run)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        if all(c['ok'] for c in out):
            break
        if i < tries - 1:
            time.sleep(4)
    return out


# --- the VPN app on this computer ----------------------------------------------------------
CLIENTS = [('vps2vpn', 'vps2vpn'), ('clash-verge', 'Clash Verge'), ('clash verge', 'Clash Verge'), ('flclash', 'FlClash'),
           ('mihomo', 'Mihomo Party'), ('nyanpasu', 'Clash Nyanpasu'), ('clash for windows', 'Clash for Windows'),
           ('clashx', 'ClashX'), ('stash', 'Stash'), ('hiddify', 'Hiddify'), ('sing-box', 'sing-box')]
LINK_FOR = {'vps2vpn': 'vps2vpn', 'clash': 'clash', 'hiddify': 'hiddify', 'sing-box': 'singbox'}
MAC_APPS = [('vps2vpn.app', 'vps2vpn'), ('Clash Verge.app', 'clash'), ('FlClash.app', 'clash'), ('Mihomo Party.app', 'clash'),
            ('Clash Nyanpasu.app', 'clash'), ('ClashX Meta.app', 'clash'), ('ClashX.app', 'clash'), ('Stash.app', 'clash'),
            ('Hiddify.app', 'hiddify'), ('SFM.app', 'sing-box')]
CLIENT_DOWNLOAD = 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest'


def client_name(path):
    low = os.path.basename(path).lower()
    for k, name in CLIENTS:
        if k in low:
            return name
    return os.path.splitext(os.path.basename(path))[0] or 'VPN 软件'


def detect_client():
    """Which installed app opens vps2vpn:// or clash:// (or hiddify:// / sing-box://) links. Read-only. {'name', 'link'} or None."""
    if os.name == 'nt':
        import winreg
        for scheme in ('vps2vpn', 'clash', 'hiddify', 'sing-box'):
            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(root, r'Software\Classes\%s\shell\open\command' % scheme) as k:
                        cmd = winreg.QueryValue(k, None)
                except OSError:
                    continue
                m = re.match(r'\s*"?([^"]+?\.exe)', cmd or '', re.I)
                if m and os.path.exists(m.group(1)):
                    return {'name': client_name(m.group(1)), 'link': LINK_FOR[scheme]}
        return None
    if sys.platform == 'darwin':
        for app, scheme in MAC_APPS:
            for d in ('/Applications', os.path.expanduser('~/Applications')):
                if os.path.isdir(os.path.join(d, app)):
                    return {'name': app[:-4], 'link': LINK_FOR[scheme]}
        return None
    for scheme in ('vps2vpn', 'clash', 'hiddify', 'sing-box'):
        try:
            r = subprocess.run(['xdg-mime', 'query', 'default', 'x-scheme-handler/' + scheme], capture_output=True,
                               text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.stdout.strip():
            return {'name': client_name(r.stdout.strip()), 'link': LINK_FOR[scheme]}
    return None


def open_link(url, schemes=LINK_SCHEMES):
    url = safe_url(url, schemes)
    if not url:
        raise ValueError('unsafe url')
    if os.name == 'nt':
        os.startfile(url)
    else:
        subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', url], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)


def auto_import(job):
    """Hand the subscription to the VPN app: it starts and asks once to add the profile (routing rules included)."""
    rec = job['rec']
    if job.get('imported') or rec.get('main') or not rec.get('links'):
        return
    c = job.get('client')
    if not c:
        return
    if job.get('no_import'):
        return
    links = rec.get('links') or {}
    raw = links.get(c['link']) or (links.get('clash') if c['link'] == 'vps2vpn' else '')
    link = safe_url(raw, LINK_SCHEMES)
    if not link:
        return
    try:
        open_link(link, LINK_SCHEMES)
        job['imported'] = True
    except (OSError, ValueError, KeyError):
        pass


# --- adding a server to one deployed before ------------------------------------------------
class PanelError(RuntimeError):
    pass


def panel_call(rec, path, body, cookie=''):
    """POST to a saved server's panel API over HTTPS. The certificate must be the one saved when it was
    deployed, or one any browser trusts (it may have switched to Let's Encrypt since)."""
    panel = safe_url(rec.get('panel'), ('https',))
    if not panel:
        raise PanelError('主服务器的面板地址无效。')
    url = urllib.parse.urlsplit(panel)
    attempts = ('pin', 'public') if rec.get('pin') else ('public',)
    for attempt in attempts:
        ctx = ssl.create_default_context()
        if attempt == 'pin':
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=30)
        try:
            conn.connect()
            if attempt == 'pin' and hashlib.sha256(conn.sock.getpeercert(True)).hexdigest() != rec['pin']:
                continue
            h = {'Content-Type': 'application/json', 'X-V2V': '1'}
            if cookie:
                h['Cookie'] = cookie
            conn.request('POST', url.path.rstrip('/') + '/api/' + path, body=json.dumps(body).encode(), headers=h)
            r = conn.getresponse()
            data = r.read(1 << 20)
            try:
                j = json.loads(data or b'{}')
            except ValueError:
                j = {}
            return r.status, j, (r.getheader('Set-Cookie') or '').split(';')[0]
        except ssl.SSLError:
            if attempt == 'public':
                raise PanelError('主服务器的证书和部署时记下的不一样，为了安全没有继续。')
        except OSError as e:
            raise PanelError('连不上主服务器的面板（%s）。' % e)
        finally:
            conn.close()
    raise PanelError('主服务器的证书和部署时记下的不一样，为了安全没有继续。')


def join_main(main, rec, name):
    """Log in to the main server's panel and paste this server's join code there."""
    if not main.get('admin_password'):
        raise PanelError('没有保存主服务器的面板密码。')
    st, j, cookie = panel_call(main, 'login', {'username': main.get('admin_user', 'admin'),
                                               'password': main['admin_password']})
    if st == 403 and j.get('error') == 'totp_required':
        return 'totp'
    if st != 200 or not cookie:
        raise PanelError('登录主服务器失败：%s（如果你改过面板密码，请到主面板手动粘贴加入码）' % (j.get('error') or st))
    st, j, _ = panel_call(main, 'servers', {'code': rec['join_code'], 'name': name}, cookie)
    if st == 200 or 'already added' in str(j.get('error', '')):
        return 'ok'
    raise PanelError('主服务器没能加上这台：%s' % (j.get('error') or st))


# --- ssh ---------------------------------------------------------------------------------------
def known_hosts_option(path):
    """-o value for a known_hosts file. ssh splits the value on spaces (it takes a list of files) and expands
    %-tokens in it, so "C:\\Users\\John Smith\\..." would otherwise become two files and the key is never kept."""
    return 'UserKnownHostsFile="%s"' % path.replace('%', '%%')


def known_host_name(host, port):
    """How ssh names the server in known_hosts (and what ssh-keygen -R wants)."""
    return host if int(port) == 22 else '[%s]:%d' % (host, int(port))


def ssh_base(job):
    os.makedirs(RECORDS, exist_ok=True)
    restrict(RECORDS)
    kh = os.path.join(RECORDS, 'known_hosts')     # persisted per user, separate from ~/.ssh
    # -F none: ignore the user's own ssh config (it may route through proxies or have bad permissions)
    cmd = ['ssh', '-F', 'none', '-p', str(job['port']), '-o', 'StrictHostKeyChecking=accept-new', '-o', known_hosts_option(kh),
           '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8']
    env = dict(os.environ)
    if job.get('key'):
        cmd += ['-i', job['key'], '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes']
    elif job.get('password'):
        # ssh asks this helper for the password instead of the keyboard
        wdir = work_dir()
        tag = secrets.token_hex(6)
        reader = os.path.join(wdir, 'askpass-%s.py' % tag)
        fd = os.open(reader, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write('import os, sys\nsys.stdout.write(os.environ.get("V2V_PW", "") + "\\n")\n')
        restrict(reader)
        helper = os.path.join(wdir, ('askpass-%s.cmd' if os.name == 'nt' else 'askpass-%s.sh') % tag)
        fd = os.open(helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\r\n' if os.name == 'nt' else '\n') as f:
            if os.name == 'nt':
                f.write('@"%s" "%s"\n' % (sys.executable, reader))
            else:
                f.write('#!/bin/sh\nexec "%s" "%s"\n' % (sys.executable, reader))
        if os.name == 'nt':
            restrict(helper)
        else:
            os.chmod(helper, 0o700)
        job['_askpass'] = [reader, helper]
        env.update(SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', DISPLAY=env.get('DISPLAY', ':0'),
                   V2V_PW=job['password'])
        cmd += ['-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'NumberOfPasswordPrompts=1']
    cmd += ['--', '%s@%s' % (job['user'], job['host'])]
    return cmd, env


def probe(cmd, env, user):
    sudo = '' if user == 'root' else 'sudo -n '
    return subprocess.run(cmd + ['echo connected; uname -sm; %sid -u' % sudo], capture_output=True, text=True,
                          errors='replace', env=env, timeout=60, stdin=subprocess.DEVNULL)


def run_job(job):
    log = job['log']

    def say(line):
        log.append(line.rstrip())

    try:
        if not shutil.which('ssh'):
            raise RuntimeError('这台电脑没有 ssh 程序。Windows 10/11：设置 > 应用 > 可选功能 > 添加“OpenSSH 客户端”。')
        if job.get('password') and not ssh_supports_askpass():
            raise RuntimeError('这台电脑的 ssh 版本太旧，不支持自动填密码。请用密钥文件，'
                               '或在「设置 > 应用 > 可选功能」里更新 OpenSSH 客户端。')
        cmd, env = ssh_base(job)
        say('connecting to %s ...' % job['host'])
        r = probe(cmd, env, job['user'])
        wanted = login_as_hint(r.stdout + r.stderr)
        if 'connected' not in r.stdout and wanted and wanted != job['user']:
            # e.g. AWS images: root's key only prints 'Please login as the user "ubuntu" rather than "root"'
            say('the server asks to log in as "%s" instead of "%s"; trying that ...' % (wanted, job['user']))
            job['user'] = wanted
            cmd = cmd[:-1] + ['%s@%s' % (wanted, job['host'])]
            r = probe(cmd, env, wanted)
        if r.returncode != 0 or 'connected' not in r.stdout:
            msg = (r.stderr or r.stdout).strip()[-400:]
            wanted = login_as_hint(r.stdout + r.stderr)
            if wanted and wanted != job['user']:
                msg += '\n-> 服务器要求用 %s 登录：把用户名改成 %s 再试。' % (wanted, wanted)
            if 'Permission denied' in msg:
                msg += '\n-> 密钥或密码不对，或者用户名不对（亚马逊一般是 ubuntu / ec2-user / admin）。'
            if 'timed out' in msg or 'Connection refused' in msg:
                msg += '\n-> 连不上服务器的 %s 端口。检查 IP 是否写对、服务器是否开机、云厂商防火墙是否放行 SSH。' % job['port']
            if 'sudo' in msg:
                msg += '\n-> 这个用户不能免密码使用 sudo，请改用 root 登录。'
            if 'IDENTIFICATION HAS CHANGED' in msg or 'Host key verification failed' in msg:
                msg += ('\n-> 这台服务器的身份和上次连接时不一样。如果你刚重装过系统或换了同一个 IP 的新服务器，这是正常的：'
                        '运行  ssh-keygen -R %s -f "%s"  后再部署一次。没有重装过就先别继续，可能有人在冒充你的服务器。'
                        % (known_host_name(job['host'], job['port']), os.path.join(RECORDS, 'known_hosts')))
            raise RuntimeError(msg)
        say(r.stdout.strip().replace('\n', ' | '))
        say('uploading vps2vpn and running the installer (1-3 minutes) ...')
        payload = base64.b64encode(package()) + b'\n'
        run_as = 'sudo -n env ' if job['user'] != 'root' else ''
        remote = ('set -e; T=$(mktemp -d); trap \'rm -rf "$T"\' EXIT; base64 -d > "$T/v.tgz"; tar -xzf "$T/v.tgz" -C "$T"; '
                  '%sV2V_AUTO=1 V2V_SRC="$T/v.tgz" bash "$T/install.sh" install') % run_as
        p = subprocess.Popen(cmd + [remote], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=env)

        def feed():
            try:
                p.stdin.write(payload)
                p.stdin.close()
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
        res = None
        for raw in p.stdout:
            line = re.sub(r'\x1b\[[0-9;]*m', '', raw.decode('utf-8', 'replace'))
            if line.startswith('V2V_RESULT:'):          # holds the new admin password: never shown in the log
                try:
                    res = json.loads(base64.b64decode(line.split(':', 1)[1].strip()))
                except ValueError:
                    pass
                continue
            say(line)
        try:
            p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
            raise RuntimeError('安装进程超时未退出')
        if p.returncode != 0 or not res:
            raise RuntimeError('安装过程出错了，详情见上面的日志')
        finish(job, res, say)
        job['state'] = 'done'
        say('done.')
    except Exception as e:      # shown on the page
        job['state'] = 'error'
        job['error'] = str(e)
    finally:
        for path in ([job.get('key')] if job.get('key') else []) + list(job.get('_askpass') or []):
            try:
                os.unlink(path)
            except OSError:
                pass
        job.pop('password', None)


def finish(job, res, say):
    rec = merge_record(job, res)
    main = load_record(job['main']) if job.get('main') else {}
    if main and main.get('host') != job['host']:
        rec['main'] = main['host']
    job['record_file'] = save_record(job['host'], rec)
    job['rec'] = rec
    for w in res.get('warnings') or []:
        say('! ' + w)
    try:
        job['client'] = detect_client()
    except Exception:       # never fail a finished install over this
        job['client'] = None
    say('checking the firewall from this computer ...')
    recheck(job)


def recheck(job):
    """Firewall check, then (once the panel port is reachable) the pending join to the main server."""
    rec = job['rec']
    job['ports'] = check_ports(job['host'], rec.get('checks') or [])
    panel_ports = [c for c in job['ports'] if c['name'] == '管理面板']
    panel_ok = bool(panel_ports) and all(c['ok'] for c in panel_ports)
    if panel_ok:            # the app downloads the subscription from the panel port
        auto_import(job)
    if rec.get('main') and job.get('join') != 'ok':
        if not panel_ok:
            job['join'], job['join_msg'] = 'wait', '先放行防火墙，再点“再检查一次”，会自动加入。'
        else:
            try:
                job['join'] = join_main(load_record(rec['main']), rec, rec.get('name') or job['host'])
                job['join_msg'] = ''
            except PanelError as e:
                job['join'], job['join_msg'] = 'fail', str(e)
    return job


def page_view(job):
    """What the page shows. The page is local and token-protected, so it may show the password."""
    out = {k: job.get(k) for k in ('state', 'log', 'error', 'ports', 'join', 'join_msg', 'record_file', 'client', 'imported')}
    out['download'] = CLIENT_DOWNLOAD
    rec = job.get('rec') or {}
    out['rec'] = {k: rec.get(k) for k in ('host', 'panel', 'admin_user', 'admin_password', 'sub_url', 'qr_url',
                                          'links', 'join_code', 'main', 'cloud', 'cloud_firewall', 'ai', 'name')}
    return out


PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vps2vpn deploy</title><style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1b2130;--mute:#667085;--line:#e4e7ec;--acc:#2563eb;--bad:#d92d20;--ok:#079455;--warn:#b54708}
@media (prefers-color-scheme:dark){:root{--bg:#0e1117;--card:#161a22;--fg:#e6e8ee;--mute:#98a2b3;--line:#283040;--acc:#5b8cff;--ok:#32d583;--bad:#f97066;--warn:#fdb022}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:640px;margin:0 auto;padding:28px 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:14px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0 0 6px}h3{font-size:15px;margin:18px 0 6px}.mute{color:var(--mute)}
label{display:block;margin:12px 0 4px;font-size:13px;color:var(--mute)}
input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg);font:inherit}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>div{flex:1;min-width:140px}
#drop{border:2px dashed var(--line);border-radius:12px;padding:22px;text-align:center;cursor:pointer;margin-top:6px}
#drop.on{border-color:var(--acc);background:rgba(37,99,235,.06)}#drop b{color:var(--acc)}
button,.btn{display:inline-block;padding:10px 14px;border:0;border-radius:10px;background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;text-align:center}
button.ghost,.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--line)}
#go{width:100%;margin-top:16px;padding:13px}button:disabled{opacity:.6}
pre{white-space:pre-wrap;word-break:break-all;font:12px/1.5 ui-monospace,Consolas,monospace;max-height:260px;overflow:auto;background:var(--bg);padding:10px;border-radius:8px}
.err{color:var(--bad)}details summary{cursor:pointer;color:var(--mute);margin-top:12px}
.btns{display:flex;gap:8px;flex-wrap:wrap}.qr{display:flex;gap:14px;align-items:center;margin-top:10px}.qr img{width:150px;height:150px;background:#fff;border-radius:8px;padding:6px}
.chk{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--line)}.chk:last-child{border:0}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.note{background:var(--bg);border-radius:10px;padding:10px 12px;margin-top:8px}
.kv{display:grid;grid-template-columns:70px 1fr auto;gap:6px 10px;align-items:center}.kv code{word-break:break-all;font:13px ui-monospace,Consolas,monospace}
a{color:var(--acc)}
</style></head><body><main>
<h1>vps2vpn 一键部署</h1><p class="mute">把你买的服务器变成自己的 VPN。填 IP、拖入密钥文件（或填密码），点按钮，剩下的全自动。</p>
<div class="card" id="form">
<label>服务器 IP</label><input id="host" placeholder="例如 203.0.113.10" autocomplete="off">
<label>SSH 密钥文件（.pem / .key / id_ed25519）——拖到下面的框里，或点击选择</label>
<div id="drop">把密钥文件拖到这里，或<b>点击选择文件</b><div id="fname" class="mute"></div></div>
<button type="button" id="clearKey" class="ghost" hidden style="margin-top:6px;padding:4px 10px;font-size:12px">清除已选密钥</button>
<input type="file" id="file" hidden>
<label>没有密钥文件？填服务器的 root 密码</label><input id="pw" type="password" autocomplete="off">
<div id="mainbox" hidden><label>这台服务器怎么用</label><select id="main"></select>
<p class="mute" style="font-size:13px;margin:4px 0 0">选“加到…下面”：两台共用同一套账号，你原来的订阅里会自动多出这台，不用重新导入。</p></div>
<details><summary>其它选项（一般不用改）</summary><div class="row">
<div><label>登录用户名</label><input id="user" value="root"></div><div><label>SSH 端口</label><input id="port" value="22"></div></div>
<p class="mute" style="font-size:13px">亚马逊 Lightsail/EC2 的用户名一般是 ubuntu、admin 或 ec2-user。</p></details>
<button id="go">一键部署</button></div>
<div class="card" id="res" hidden></div>
<div class="card" id="out" hidden><div id="status"></div><details id="logbox"><summary>安装日志</summary><pre id="log"></pre></details></div>
<p class="mute" style="font-size:12px">密钥和密码只用于这一次连接，用完立刻删除。面板登录信息只保存在你这台电脑的用户文件夹里（vps2vpn 文件夹）。</p>
</main><script>
const T='__TOKEN__';let key=null,jobId='';const $=s=>document.querySelector(s);
const el=(tag,attrs,...kids)=>{const e=document.createElement(tag);for(const k in attrs||{}){if(k==='text')e.textContent=attrs[k];else if(k.startsWith('on'))e[k]=attrs[k];else e.setAttribute(k,attrs[k])}kids.filter(Boolean).forEach(c=>e.append(c));return e};
const LINK_SCHEMES=['vps2vpn','clash','hiddify','sing-box','shadowrocket'];
function safeHref(u,schemes){if(typeof u!=='string'||!u||/^-|[\x00-\x20\x7f]/.test(u))return '';try{const p=new URL(u);return schemes.includes(p.protocol.slice(0,-1).toLowerCase())?u:''}catch{return ''}}
const drop=$('#drop'),file=$('#file'),clearKey=$('#clearKey');
function take(f){if(!f)return;if(f.size>32768){alert('这不像密钥文件（太大了）');return}
 const r=new FileReader();r.onload=()=>{key=r.result;$('#fname').textContent='已选：'+f.name;clearKey.hidden=false;
 if(/\.pem$/i.test(f.name)&&/LightsailDefaultKey|ec2|aws/i.test(f.name)&&$('#user').value==='root'){$('#user').value='ubuntu'}};r.readAsText(f)}
clearKey.onclick=()=>{key=null;file.value='';$('#fname').textContent='';clearKey.hidden=true};
drop.onclick=()=>file.click();file.onchange=()=>take(file.files[0]);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('on')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('on')}));
drop.addEventListener('drop',ev=>take(ev.dataTransfer.files[0]));
(async()=>{try{const r=await fetch('/records?t='+T);if(!r.ok)return;const list=await r.json();if(!list.length)return;const s=$('#main');
 s.append(el('option',{value:'',text:'单独使用（第一台，或不想和别的服务器共用账号）'}));
 list.forEach(x=>{const o=el('option',{value:x.host,text:'加到 '+x.host+' 下面（共用账号和订阅）'+(x.can?'':' —— 没保存它的面板密码，不能自动加')});if(!x.can)o.disabled=true;s.append(o)});
 $('#mainbox').hidden=false}catch{}})();
function fallbackCopy(t,done){const a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.append(a);a.select();try{document.execCommand('copy');done()}catch{}finally{a.remove()}}
function copy(t,b){const done=()=>{if(!b.dataset.orig)b.dataset.orig=b.textContent;b.textContent='已复制';clearTimeout(b._tm);b._tm=setTimeout(()=>{b.textContent=b.dataset.orig},1500)};
 if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done).catch(()=>fallbackCopy(t,done))}else fallbackCopy(t,done)}
function render(s){const r=s.rec||{},box=$('#res');box.hidden=false;box.replaceChildren();
 box.append(el('h2',{text:'✅ 部署成功'}));
 if(r.main){const m={ok:['ok','已加入主服务器 '+r.main+'：你在那边的订阅里会自动多出这台服务器（在 Clash / Shadowrocket 里点一下“更新订阅”）。'],
  totp:['bad','主服务器开了两步验证，没法自动加入。请打开主服务器面板 → 多服务器 → 粘贴下面的加入码。'],
  wait:['bad',s.join_msg],fail:['bad','没能自动加入主服务器：'+(s.join_msg||'')+' 你可以打开主服务器面板 → 多服务器 → 粘贴下面的加入码。']}[s.join]||['mute',''];
  box.append(el('p',{class:m[0],text:m[1]}));
  if(s.join==='totp'||s.join==='fail'){const b=el('button',{class:'ghost',text:'复制加入码'});b.onclick=()=>copy(r.join_code,b);box.append(b)}}
 if(r.ai&&r.ai.summary){const a=r.ai;box.append(el('div',{class:'note'},el('b',{text:'AI 可用性（从服务器测试）：'+a.summary}),
  el('div',{class:'mute',text:[a.place,a.org,a.kind].filter(Boolean).join(' · ')}),...(a.advice||[]).map(x=>el('div',{text:x})),
  el('div',{class:'mute',style:'font-size:13px',text:'结果只作参考；以后可以在管理面板 → 系统里重新检测。'})))}
 const subUrl=safeHref(r.sub_url,['http','https']);
 if(!r.main&&subUrl){box.append(el('h3',{text:'① 把 VPN 装到你的设备上'}));
  const c=s.client;
  if(c&&s.imported)box.append(el('div',{class:'note'},el('b',{class:'ok',text:'检测到你电脑上的 '+c.name+'，已经自动打开它导入。'}),
   el('div',{text:'在它弹出的窗口点“确定/导入”，然后在软件里选中这个配置、打开“系统代理”开关就能用了。分流规则（国内网站直连、国外走代理）已经写好在里面，不用自己设置。'})));
  else if(c)box.append(el('p',{text:'检测到你电脑上的 '+c.name+'。防火墙放行后会自动导入，也可以直接点下面的按钮。'}));
  else{const dl=safeHref(s.download,['https']);box.append(el('div',{class:'note'},el('b',{text:'没检测到电脑上的 VPN 软件。'}),
   el('div',{text:'推荐装免费开源的 Clash Verge Rev（Windows 下载名字里带 setup 的 .exe，Mac 下载 .dmg）。装好后回来点“导入到 Clash（电脑）”。'}),
   dl?el('a',{href:dl,target:'_blank',rel:'noopener noreferrer',text:'打开下载页'}):null))}
  const L=r.links||{};const b3=el('button',{class:'ghost',text:'复制订阅链接'});b3.onclick=()=>copy(subUrl,b3);
  const mainLink=safeHref((c&&L[c.link])||L.clash,LINK_SCHEMES),srLink=safeHref(L.shadowrocket_conf,LINK_SCHEMES);
  box.append(el('div',{class:'btns'},mainLink?el('a',{class:'btn',href:mainLink,text:c?(s.imported?'再导入一次到 ':'导入到 ')+c.name:'导入到 Clash（电脑）'}):null,
   srLink?el('a',{class:'btn',href:srLink,text:'导入到 Shadowrocket'}):null,b3));
  const qrSrc=safeHref(r.qr_url,['http','https']);
  box.append(el('div',{class:'qr'},qrSrc?el('img',{src:qrSrc,alt:'QR'}):null,el('div',{class:'mute',text:'手机打开 Shadowrocket 或 Clash，扫这个二维码就导入好了。电脑上没反应的话：先装好 Clash Verge / FlClash，再点上面的按钮；或者复制订阅链接，在软件里“新建订阅”粘贴。'})))}
 box.append(el('h3',{text:(r.main?'':'② ')+'防火墙检查（从你这台电脑测试）'}));
 const bad=(s.ports||[]).filter(c=>!c.ok);
 (s.ports||[]).forEach(c=>box.append(el('div',{class:'chk'},el('span',{text:c.name+'  '+c.proto.toUpperCase()+' '+c.port}),el('span',{class:c.ok?'ok':'bad',text:c.ok?'✓ 通了':'✗ 不通'}))));
 if(bad.length){box.append(el('div',{class:'note'},el('b',{text:'有端口被云服务商的防火墙挡住了。'}),el('div',{text:r.cloud_firewall?('这台在 '+r.cloud+' 上。'+r.cloud_firewall):'请到云服务商的网页控制台，找“防火墙 / 安全组”，添加一条规则：协议选“全部/所有”，来源 0.0.0.0/0。'}),
  el('div',{class:'mute',text:'需要放行：'+bad.map(c=>c.proto.toUpperCase()+' '+c.port).join('、')})));
  const rb=el('button',{text:'我已放行，再检查一次'});rb.onclick=async()=>{rb.disabled=true;rb.textContent='正在检查…';
   try{const res=await fetch('/recheck?t='+T+'&id='+encodeURIComponent(jobId),{method:'POST'});if(!res.ok)throw new Error('HTTP '+res.status);const x=await res.json();render(x)}
   catch(e){rb.disabled=false;rb.textContent='我已放行，再检查一次';alert('检查失败：'+(e.message||e))}};box.append(el('p',{},rb))}
 else if(s.ports&&s.ports.length)box.append(el('p',{class:'ok',text:'全部通了，可以用了。'}));
 box.append(el('h3',{text:(r.main?'':'③ ')+'管理面板（加用户、看流量）'}));
 const panelUrl=safeHref(r.panel,['https']);
 if(panelUrl){const pw=r.admin_password||'';const pv=el('code',{text:pw?'••••••••••••':'（用你自己设置的密码）'});
  const show=el('button',{class:'ghost',text:'显示'});show.onclick=()=>{pv.textContent=pv.textContent===pw?'••••••••••••':pw;show.textContent=pv.textContent===pw?'隐藏':'显示'};
  const cp=el('button',{class:'ghost',text:'复制'});cp.onclick=()=>copy(pw,cp);const cu=el('button',{class:'ghost',text:'打开'});cu.onclick=()=>window.open(panelUrl,'_blank','noopener,noreferrer');
  box.append(el('div',{class:'kv'},el('span',{class:'mute',text:'地址'}),el('code',{text:panelUrl}),cu,el('span',{class:'mute',text:'用户名'}),el('code',{text:r.admin_user||'admin'}),el('span'),
   el('span',{class:'mute',text:'密码'}),pv,pw?el('div',{class:'btns'},show,cp):el('span')));
  box.append(el('p',{class:'mute',style:'font-size:13px',text:'浏览器若提示“不安全”，点“高级 → 继续访问”即可（照样加密）。这些信息已保存在：'+(s.record_file||'')}))}}
$('#go').onclick=async()=>{
 const host=$('#host').value.trim();if(!host)return alert('先填服务器 IP');if(!key&&!$('#pw').value)return alert('拖入密钥文件，或者填密码');
 $('#go').disabled=true;$('#out').hidden=false;$('#res').hidden=true;$('#status').textContent='正在部署，大约 1-3 分钟，别关这个页面…';
 let r,j;try{r=await fetch('/start?t='+T,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,key,pw:$('#pw').value,user:$('#user').value.trim()||'root',port:$('#port').value.trim()||'22',main:$('#main').value||''})});
  j=await r.json()}catch(e){$('#status').replaceChildren(el('span',{class:'err',text:'无法连接本地部署服务：'+(e.message||e)}));$('#go').disabled=false;return}
 if(!r.ok){$('#status').replaceChildren(el('span',{class:'err',text:j.error||'启动失败'}));$('#go').disabled=false;return}
 jobId=j.id;
 const poll=async()=>{let s;try{const pr=await fetch('/job?t='+T+'&id='+encodeURIComponent(j.id));if(!pr.ok)throw new Error('HTTP '+pr.status);s=await pr.json()}catch(e){$('#status').replaceChildren(el('span',{class:'err',text:'获取进度失败：'+(e.message||e)}));$('#go').disabled=false;return}
  $('#log').textContent=(s.log||[]).join('\n');$('#log').scrollTop=1e9;
  if(s.state==='running')return setTimeout(poll,1000);$('#go').disabled=false;
  if(s.state==='done'){$('#status').textContent='部署完成。';render(s);$('#res').scrollIntoView({behavior:'smooth'})}
  else{$('#logbox').open=true;$('#status').replaceChildren(el('span',{class:'err',text:'失败：'+(s.error||'未知错误')}))}};poll()}
</script></body></html>'''


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype='application/json'):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' http: https: data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(b)

    def ok_token(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        # bytes: compare_digest raises TypeError on a str with non-ASCII characters (?t=%E4%B8%AD)
        return secrets.compare_digest((q.get('t') or [''])[0].encode('utf-8'), TOKEN.encode('ascii'))

    def job(self):
        jid = (urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('id') or [''])[0]
        return JOBS.get(jid)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if not self.ok_token():
            return self.reply(404, '{}')
        if path == '/':
            return self.reply(200, PAGE.replace('__TOKEN__', TOKEN), 'text/html')
        if path == '/records':        # which servers can be the main one (no passwords sent)
            return self.reply(200, json.dumps([{'host': r['host'], 'can': bool(r.get('admin_password') and r.get('panel'))}
                                               for r in load_records()]))
        if path == '/job':
            job = self.job()
            return self.reply(200, json.dumps(page_view(job))) if job else self.reply(404, '{}')
        self.reply(404, '{}')

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if not self.ok_token():
            return self.reply(403, '{}')
        if path == '/recheck':
            job = self.job()
            if not job or job.get('state') != 'done':
                return self.reply(404, '{}')
            return self.reply(200, json.dumps(page_view(recheck(job))))
        if path != '/start':
            return self.reply(404, '{}')
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return self.reply(400, json.dumps({'error': '请求格式不对'}))
        if length < 0 or length > (1 << 20):
            return self.reply(413, json.dumps({'error': '请求内容太大'}))
        try:
            d = json.loads(self.rfile.read(length) or b'{}')
        except ValueError:
            return self.reply(400, json.dumps({'error': '请求格式不对'}))
        if not isinstance(d, dict):
            return self.reply(400, json.dumps({'error': '请求格式不对'}))
        job, err = new_job(str(d.get('host', '')), str(d.get('user', 'root')), str(d.get('port', '22')),
                           str(d.get('main', '')))
        if err:
            return self.reply(400, json.dumps({'error': err}))
        if d.get('key'):
            bad = key_problem(str(d['key']))
            if bad:
                return self.reply(400, json.dumps({'error': bad}))
            job['key'] = write_key(str(d['key']))
        elif d.get('pw'):
            job['password'] = str(d['pw'])
        else:
            return self.reply(400, json.dumps({'error': '需要密钥文件或密码'}))
        jid = secrets.token_hex(6)
        JOBS[jid] = job
        threading.Thread(target=run_job, args=(job,), daemon=True).start()
        self.reply(200, json.dumps({'id': jid}))


def new_job(host, user, port, main=''):
    host, user, port = host.strip().strip('[]'), user.strip(), port.strip()
    if not re.fullmatch(r'[A-Za-z0-9.:\-]{3,255}', host) or host.startswith('-'):
        return None, 'IP 地址格式不对'
    if not re.fullmatch(r'[a-z_][a-z0-9_.-]{0,31}', user) or not port.isdigit() or not 1 <= int(port) <= 65535:
        return None, '用户名或端口格式不对'
    if main and (main == host or not load_record(main).get('admin_password')):
        return None, '选的主服务器不能用（不能加到它自己下面，或者没保存它的面板密码）'
    return {'state': 'running', 'log': [], 'host': host, 'user': user, 'port': int(port), 'main': main}, ''


def key_problem(text):
    """A plain-language reason this file cannot be used as an ssh key, or '' if it looks usable."""
    t = text.replace('\r\n', '\n').strip()
    if t.startswith('PuTTY-User-Key-File'):
        return ('这是 PuTTY 格式的密钥（.ppk），ssh 不能直接用。请用 PuTTYgen 打开它，'
                '点「Conversions > Export OpenSSH key」另存一份，再把新文件拖进来。')
    if 'PRIVATE KEY' not in t:
        if re.match(r'(ssh-(rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+) AAAA', t):
            return '这是公钥（通常是 .pub 文件），要用的是同名但不带 .pub 的私钥文件。'
        return '这不是私钥文件（里面没有 PRIVATE KEY）。请选 .pem / .key / id_ed25519 这类文件。'
    if 'ENCRYPTED' in t.split('\n\n')[0] or encrypted_openssh_key(t):
        return ('这个私钥设了密码保护，部署工具不能替你输入。请换一个没有密码的密钥，'
                '或者先复制一份密钥，再在命令行运行  ssh-keygen -p -f 复制出的文件  去掉密码后拖入那份。')
    return ''


def encrypted_openssh_key(text):
    """True for a new-format OpenSSH key protected by a passphrase (its cipher name is not 'none')."""
    m = re.search(r'-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END', text, re.S)
    if not m:
        return False
    try:
        raw = base64.b64decode(''.join(m.group(1).split()))
    except ValueError:
        return False
    magic = b'openssh-key-v1\x00'
    if not raw.startswith(magic) or len(raw) < len(magic) + 4:
        return False
    n = int.from_bytes(raw[len(magic):len(magic) + 4], 'big')
    return raw[len(magic) + 4:len(magic) + 4 + n] != b'none'


def login_as_hint(text):
    """Cloud images (AWS and others) answer root logins with 'Please login as the user "ubuntu" ...'."""
    m = re.search(r'login as the user "?([a-z_][a-z0-9_.-]{0,31})"? rather than', text or '')
    return m.group(1) if m else ''


def ssh_supports_askpass():
    """Windows' built-in OpenSSH before 8.4 ignores SSH_ASKPASS_REQUIRE, so it cannot be handed a password."""
    if os.name != 'nt':
        return True
    try:
        v = subprocess.run(['ssh', '-V'], capture_output=True, text=True, errors='replace', timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True
    m = re.search(r'OpenSSH_for_Windows_(\d+)\.(\d+)', (v.stderr or '') + (v.stdout or ''))
    return not m or (int(m.group(1)), int(m.group(2))) >= (8, 4)


def write_key(text):
    path = os.path.join(work_dir(), 'key-' + secrets.token_hex(4))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', newline='\n') as f:
        f.write(text.replace('\r\n', '\n').strip() + '\n')
    restrict(path)
    return path


def restrict(path):
    """Only this user may read it. OpenSSH refuses keys others can read; on Windows that means the ACL."""
    if os.name != 'nt':
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
        return
    user = os.environ.get('USERNAME', '')
    grant = '%s:(OI)(CI)F' % user if os.path.isdir(path) else '%s:F' % user
    subprocess.run(['icacls', path, '/inheritance:r', '/grant:r', grant], capture_output=True)


restrict_key_file = restrict      # old name


def headless(argv):
    """python3 deploy/deploy.py --headless HOST KEYFILE [USER] [--main MAIN_HOST]   (prints no secrets)"""
    try:
        sys.stdout.reconfigure(errors='replace')     # a Chinese Windows console cannot show ✓
    except (AttributeError, ValueError):
        pass
    main = ''
    if '--main' in argv:
        i = argv.index('--main')
        main = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    host, keyfile = argv[0], argv[1]
    job, err = new_job(host, argv[2] if len(argv) > 2 else 'root', '22', main)
    if err:
        sys.exit(err)
    job['no_import'] = True         # tests never touch the VPN app on this computer
    with open(keyfile, encoding='utf-8', errors='replace') as f:
        text = f.read()
    bad = key_problem(text)
    if bad:
        sys.exit(bad)
    job['key'] = write_key(text)
    run_job(job)
    print('\n'.join(job['log']))
    v = page_view(job)
    rec = v.pop('rec')
    v.pop('log')
    v['saved_password'] = bool(rec.get('admin_password'))
    v['has_sub_url'] = bool(rec.get('sub_url'))
    v['name'] = rec.get('name')
    v['ai'] = (rec.get('ai') or {}).get('summary', '')
    print(json.dumps(v))
    sys.exit(0 if job['state'] == 'done' else 1)


def main():
    if sys.argv[1:2] == ['--headless']:
        try:
            return headless(sys.argv[2:])
        finally:
            if WORK:
                shutil.rmtree(WORK, ignore_errors=True)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), H)
    url = 'http://127.0.0.1:%d/?t=%s' % (srv.server_address[1], TOKEN)
    print('vps2vpn deployer is running. If your browser did not open, visit:\n  ' + url)
    print('Close this window when you are done.', flush=True)
    if not port and os.environ.get('V2V_NO_BROWSER') != '1':      # a fixed port means a developer is driving it
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if WORK:
            shutil.rmtree(WORK, ignore_errors=True)


if __name__ == '__main__':
    main()
