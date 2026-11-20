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
import ipaddress
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
WORK = tempfile.mkdtemp(prefix='vps2vpn-deploy-')
TOKEN = secrets.token_urlsafe(16)          # only the browser tab we open can use this local page
RECORDS = os.environ.get('V2V_RECORDS') or os.path.join(os.path.expanduser('~'), 'vps2vpn')
JOBS = {}


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


def save_record(host, rec):
    os.makedirs(RECORDS, exist_ok=True)
    restrict(RECORDS)
    p = record_path(host)
    fd, tmp = tempfile.mkstemp(prefix='.record-', dir=RECORDS)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        restrict(p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return p


def merge_record(job, res):
    """Remember this server. An upgrade has no new password, so the one saved earlier is kept."""
    a = res.get('auto') or {}
    rec = load_record(job['host'])
    rec.update({k: a[k] for k in ('panel', 'pin', 'join_code', 'name', 'user', 'sub_url', 'qr_url', 'links', 'checks', 'ai')
                if a.get(k) is not None})
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
    fam = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for _ in range(2):
            try:
                s.sendto(pkt, (host, int(port)))
                d, _ = s.recvfrom(2048)
                if len(d) >= 7 and d[0] & 0x80 and d[1:5] == b'\0\0\0\0':
                    return True
            except socket.timeout:
                continue
            except OSError:
                return False
    return False


def check_ports(host, checks, tries=3):
    """[{proto, port, name, ok}]. Retries a few times: the services were only just started."""
    out = [{'proto': c[0], 'port': int(c[1]), 'name': c[2], 'ok': False} for c in checks]
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
CLIENTS = [('clash-verge', 'Clash Verge'), ('clash verge', 'Clash Verge'), ('flclash', 'FlClash'), ('mihomo', 'Mihomo Party'),
           ('nyanpasu', 'Clash Nyanpasu'), ('clash for windows', 'Clash for Windows'), ('clashx', 'ClashX'),
           ('stash', 'Stash'), ('hiddify', 'Hiddify'), ('sing-box', 'sing-box')]
LINK_FOR = {'clash': 'clash', 'hiddify': 'hiddify', 'sing-box': 'singbox'}
MAC_APPS = [('Clash Verge.app', 'clash'), ('FlClash.app', 'clash'), ('Mihomo Party.app', 'clash'), ('Clash Nyanpasu.app', 'clash'),
            ('ClashX Meta.app', 'clash'), ('ClashX.app', 'clash'), ('Stash.app', 'clash'), ('Hiddify.app', 'hiddify'),
            ('SFM.app', 'sing-box')]
CLIENT_DOWNLOAD = 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest'


def client_name(path):
    low = os.path.basename(path).lower()
    for k, name in CLIENTS:
        if k in low:
            return name
    return os.path.splitext(os.path.basename(path))[0] or 'VPN 软件'


def detect_client():
    """Which installed app opens clash:// (or hiddify:// / sing-box://) links. Read-only. {'name', 'link'} or None."""
    if os.name == 'nt':
        import winreg
        for scheme in ('clash', 'hiddify', 'sing-box'):
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
    for scheme in ('clash', 'hiddify', 'sing-box'):
        try:
            r = subprocess.run(['xdg-mime', 'query', 'default', 'x-scheme-handler/' + scheme], capture_output=True,
                               text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.stdout.strip():
            return {'name': client_name(r.stdout.strip()), 'link': LINK_FOR[scheme]}
    return None


def open_link(url):
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
    try:
        open_link(rec['links'][c['link']])
        job['imported'] = True
    except (OSError, KeyError):
        pass


# --- adding a server to one deployed before ------------------------------------------------
class PanelError(RuntimeError):
    pass


def panel_call(rec, path, body, cookie=''):
    """POST to a saved server's panel API over HTTPS. The certificate must be the one saved when it was
    deployed, or one any browser trusts (it may have switched to Let's Encrypt since)."""
    url = urllib.parse.urlsplit(rec['panel'])
    if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None:
        raise PanelError('Panel URL must use HTTPS without user information')
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
def ssh_base(job):
    os.makedirs(RECORDS, exist_ok=True)
    restrict(RECORDS)
    kh = os.path.join(RECORDS, 'known_hosts')
    fd = os.open(kh, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    restrict(kh)
    # -F none: ignore the user's own ssh config (it may route through proxies or have bad permissions)
    cmd = ['ssh', '-F', 'none', '-p', str(job['port']), '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + kh,
           '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8']
    env = dict(os.environ)
    if job.get('key'):
        cmd += ['-i', job['key'], '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes']
    elif job.get('password'):
        # ssh asks this helper for the password instead of the keyboard
        reader = os.path.join(WORK, 'askpass.py')
        with open(reader, 'w') as f:
            f.write('import os, sys\nsys.stdout.write(os.environ.get("V2V_PW", "") + "\\n")\n')
        helper = os.path.join(WORK, 'askpass.cmd' if os.name == 'nt' else 'askpass.sh')
        with open(helper, 'w') as f:
            if os.name == 'nt':
                f.write('@"%s" "%s"\r\n' % (sys.executable, reader))
            else:
                f.write('#!/bin/sh\nexec "%s" "%s"\n' % (sys.executable, reader))
        os.chmod(helper, 0o700)
        env.update(SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', DISPLAY=env.get('DISPLAY', ':0'),
                   V2V_PW=job['password'])
        cmd += ['-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'NumberOfPasswordPrompts=1']
    cmd.append('%s@%s' % (job['user'], job['host']))
    return cmd, env


def run_job(job):
    log = job['log']

    def say(line):
        log.append(line.rstrip())

    try:
        if not shutil.which('ssh'):
            raise RuntimeError('这台电脑没有 ssh 程序。Windows 10/11：设置 > 应用 > 可选功能 > 添加“OpenSSH 客户端”。')
        cmd, env = ssh_base(job)
        sudo = '' if job['user'] == 'root' else 'sudo -n '
        say('connecting to %s ...' % job['host'])
        r = subprocess.run(cmd + ['echo connected; uname -sm; %sid -u' % sudo], capture_output=True, text=True,
                           env=env, timeout=60, stdin=subprocess.DEVNULL)
        if r.returncode != 0 or 'connected' not in r.stdout:
            msg = (r.stderr or r.stdout).strip()[-400:]
            if 'Permission denied' in msg:
                msg += '\n-> 密钥或密码不对，或者用户名不对（亚马逊一般是 ubuntu / ec2-user / admin）。'
            if 'timed out' in msg or 'Connection refused' in msg:
                msg += '\n-> 连不上服务器的 %s 端口。检查 IP 是否写对、服务器是否开机、云厂商防火墙是否放行 SSH。' % job['port']
            if 'sudo' in msg:
                msg += '\n-> 这个用户不能免密码使用 sudo，请改用 root 登录。'
            raise RuntimeError(msg)
        say(r.stdout.strip().replace('\n', ' | '))
        say('uploading vps2vpn and running the installer (1-3 minutes) ...')
        payload = base64.b64encode(package()) + b'\n'
        run_as = 'sudo -n env ' if job['user'] != 'root' else ''
        remote = ('set -e; T=$(mktemp -d); base64 -d > "$T/v.tgz"; tar -xzf "$T/v.tgz" -C "$T"; '
                  '%sV2V_AUTO=1 V2V_SRC="$T/v.tgz" bash "$T/install.sh" install; rm -rf "$T"') % run_as
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
        p.wait()
        if p.returncode != 0 or not res:
            raise RuntimeError('安装过程出错了，详情见上面的日志')
        finish(job, res, say)
        job['state'] = 'done'
        say('done.')
    except Exception as e:      # shown on the page
        job['state'] = 'error'
        job['error'] = str(e)
    finally:
        if job.get('key'):
            try:
                os.unlink(job['key'])
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
    panel_checks = [c for c in job['ports'] if c['name'] == '管理面板']
    panel_ok = bool(panel_checks) and all(c['ok'] for c in panel_checks)
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
const drop=$('#drop'),file=$('#file');
function take(f){if(!f)return;if(f.size>32768){alert('这不像密钥文件（太大了）');return}
 const r=new FileReader();r.onload=()=>{key=r.result;$('#fname').textContent='已选：'+f.name;
 if(/\.pem$/i.test(f.name)&&/LightsailDefaultKey|ec2|aws/i.test(f.name)&&$('#user').value==='root'){$('#user').value='ubuntu'}};r.readAsText(f)}
drop.onclick=()=>file.click();file.onchange=()=>take(file.files[0]);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('on')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('on')}));
drop.addEventListener('drop',ev=>take(ev.dataTransfer.files[0]));
fetch('/records?t='+T).then(r=>r.json()).then(list=>{if(!list.length)return;const s=$('#main');
 s.append(el('option',{value:'',text:'单独使用（第一台，或不想和别的服务器共用账号）'}));
 list.forEach(x=>{const o=el('option',{value:x.host,text:'加到 '+x.host+' 下面（共用账号和订阅）'+(x.can?'':' —— 没保存它的面板密码，不能自动加')});if(!x.can)o.disabled=true;s.append(o)});
 $('#mainbox').hidden=false});
function copy(t,b){navigator.clipboard.writeText(t).then(()=>{const o=b.textContent;b.textContent='已复制';setTimeout(()=>b.textContent=o,1500)})}
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
 if(!r.main&&r.sub_url){box.append(el('h3',{text:'① 把 VPN 装到你的设备上'}));
  const c=s.client;
  if(c&&s.imported)box.append(el('div',{class:'note'},el('b',{class:'ok',text:'检测到你电脑上的 '+c.name+'，已经自动打开它导入。'}),
   el('div',{text:'在它弹出的窗口点“确定/导入”，然后在软件里选中这个配置、打开“系统代理”开关就能用了。分流规则（国内网站直连、国外走代理）已经写好在里面，不用自己设置。'})));
  else if(c)box.append(el('p',{text:'检测到你电脑上的 '+c.name+'。防火墙放行后会自动导入，也可以直接点下面的按钮。'}));
  else box.append(el('div',{class:'note'},el('b',{text:'没检测到电脑上的 VPN 软件。'}),
   el('div',{text:'推荐装免费开源的 Clash Verge Rev（Windows 下载名字里带 setup 的 .exe，Mac 下载 .dmg）。装好后回来点“导入到 Clash（电脑）”。'}),
   el('a',{href:s.download,target:'_blank',rel:'noopener',text:'打开下载页'})));
  const L=r.links||{};const b3=el('button',{class:'ghost',text:'复制订阅链接'});b3.onclick=()=>copy(r.sub_url,b3);
  box.append(el('div',{class:'btns'},el('a',{class:'btn',href:(c&&L[c.link])||L.clash||'#',text:c?(s.imported?'再导入一次到 ':'导入到 ')+c.name:'导入到 Clash（电脑）'}),
   el('a',{class:'btn',href:L.shadowrocket_conf||'#',text:'导入到 Shadowrocket'}),b3));
  box.append(el('div',{class:'qr'},el('img',{src:r.qr_url,alt:'QR'}),el('div',{class:'mute',text:'手机打开 Shadowrocket 或 Clash，扫这个二维码就导入好了。电脑上没反应的话：先装好 Clash Verge / FlClash，再点上面的按钮；或者复制订阅链接，在软件里“新建订阅”粘贴。'})))}
 box.append(el('h3',{text:(r.main?'':'② ')+'防火墙检查（从你这台电脑测试）'}));
 const bad=(s.ports||[]).filter(c=>!c.ok);
 (s.ports||[]).forEach(c=>box.append(el('div',{class:'chk'},el('span',{text:c.name+'  '+c.proto.toUpperCase()+' '+c.port}),el('span',{class:c.ok?'ok':'bad',text:c.ok?'✓ 通了':'✗ 不通'}))));
 if(bad.length){box.append(el('div',{class:'note'},el('b',{text:'有端口被云服务商的防火墙挡住了。'}),el('div',{text:r.cloud_firewall?('这台在 '+r.cloud+' 上。'+r.cloud_firewall):'请到云服务商的网页控制台，找“防火墙 / 安全组”，添加一条规则：协议选“全部/所有”，来源 0.0.0.0/0。'}),
  el('div',{class:'mute',text:'需要放行：'+bad.map(c=>c.proto.toUpperCase()+' '+c.port).join('、')})));
  const rb=el('button',{text:'我已放行，再检查一次'});rb.onclick=async()=>{rb.disabled=true;rb.textContent='正在检查…';
   const x=await (await fetch('/recheck?t='+T+'&id='+jobId,{method:'POST'})).json();render(x)};box.append(el('p',{},rb))}
 else if(s.ports&&s.ports.length)box.append(el('p',{class:'ok',text:'全部通了，可以用了。'}));
 box.append(el('h3',{text:(r.main?'':'③ ')+'管理面板（加用户、看流量）'}));
 if(r.panel){const pw=r.admin_password||'';const pv=el('code',{text:pw?'••••••••••••':'（用你自己设置的密码）'});
  const show=el('button',{class:'ghost',text:'显示'});show.onclick=()=>{pv.textContent=pv.textContent===pw?'••••••••••••':pw;show.textContent=pv.textContent===pw?'隐藏':'显示'};
  const cp=el('button',{class:'ghost',text:'复制'});cp.onclick=()=>copy(pw,cp);const cu=el('button',{class:'ghost',text:'打开'});cu.onclick=()=>window.open(r.panel,'_blank','noopener');
  box.append(el('div',{class:'kv'},el('span',{class:'mute',text:'地址'}),el('code',{text:r.panel}),cu,el('span',{class:'mute',text:'用户名'}),el('code',{text:r.admin_user||'admin'}),el('span'),
   el('span',{class:'mute',text:'密码'}),pv,pw?el('div',{class:'btns'},show,cp):el('span')));
  box.append(el('p',{class:'mute',style:'font-size:13px',text:'浏览器若提示“不安全”，点“高级 → 继续访问”即可（照样加密）。这些信息已保存在：'+(s.record_file||'')}))}}
$('#go').onclick=async()=>{
 const host=$('#host').value.trim();if(!host)return alert('先填服务器 IP');if(!key&&!$('#pw').value)return alert('拖入密钥文件，或者填密码');
 $('#go').disabled=true;$('#out').hidden=false;$('#res').hidden=true;$('#status').textContent='正在部署，大约 1-3 分钟，别关这个页面…';
 const r=await fetch('/start?t='+T,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,key,pw:$('#pw').value,user:$('#user').value.trim()||'root',port:$('#port').value.trim()||'22',main:$('#main').value||''})});
 const j=await r.json();if(!r.ok){$('#status').innerHTML='<span class="err"></span>';$('#status .err').textContent=j.error;$('#go').disabled=false;return}
 jobId=j.id;
 const poll=async()=>{const s=await (await fetch('/job?t='+T+'&id='+j.id)).json();$('#log').textContent=s.log.join('\n');$('#log').scrollTop=1e9;
  if(s.state==='running')return setTimeout(poll,1000);$('#go').disabled=false;
  if(s.state==='done'){$('#status').textContent='部署完成。';render(s);$('#res').scrollIntoView({behavior:'smooth'})}
  else{$('#logbox').open=true;$('#status').innerHTML='<span class="err"></span>';$('#status .err').textContent='失败：'+(s.error||'未知错误')}};poll()}
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
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(b)

    def ok_token(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        return secrets.compare_digest((q.get('t') or [''])[0], TOKEN)

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
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0].strip()) or self.headers.get('Transfer-Encoding'):
                raise ValueError('invalid request framing')
            n = int(lengths[0])
            if not 0 <= n <= 65536:
                raise ValueError('request too large')
            self.connection.settimeout(15)
            raw = self.rfile.read(n)
            if len(raw) != n:
                raise ValueError('incomplete request')
            d = json.loads(raw or b'{}')
            if not isinstance(d, dict):
                raise ValueError('object required')
        except (ValueError, UnicodeError, OSError):
            self.close_connection = True
            return self.reply(400, json.dumps({'error': 'invalid request'}))
        job, err = new_job(str(d.get('host', '')), str(d.get('user', 'root')), str(d.get('port', '22')),
                           str(d.get('main', '')))
        if err:
            return self.reply(400, json.dumps({'error': err}))
        if d.get('key'):
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
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', host):
            return None, 'IP 地址格式不对'
    if not re.fullmatch(r'[a-z_][a-z0-9_.-]{0,31}', user) or not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
        return None, '用户名或端口格式不对'
    if main and (main == host or not load_record(main).get('admin_password')):
        return None, '选的主服务器不能用（不能加到它自己下面，或者没保存它的面板密码）'
    return {'state': 'running', 'log': [], 'host': host, 'user': user, 'port': int(port), 'main': main}, ''


def write_key(text):
    path = os.path.join(WORK, 'key-' + secrets.token_hex(4))
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
    with open(keyfile, encoding='utf-8') as f:
        job['key'] = write_key(f.read())
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
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == '__main__':
    main()
