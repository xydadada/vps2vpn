"""Talking to the operating system: services, kernel tuning, port hopping, firewall, health."""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request

from . import paths


def run(cmd, check=False, timeout=60):
    if not paths.LIVE:
        return subprocess.CompletedProcess(cmd, 0, '', '')
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError('%s failed: %s' % (' '.join(cmd), (r.stderr or r.stdout)[-300:]))
    return r


def systemctl(*args):
    return run(['systemctl'] + list(args))


def unit_active(unit):
    if not paths.LIVE:
        return None
    return run(['systemctl', 'is-active', unit]).stdout.strip() == 'active'


# --- kernel network tuning ----------------------------------------------------------
def mem_total_mb():
    try:
        with open('/proc/meminfo') as f:
            return int(re.search(r'MemTotal:\s+(\d+)', f.read()).group(1)) // 1024
    except (OSError, AttributeError):
        return 1024


def sysctl_text(mem_mb=None):
    """BBR + fq, and socket buffers big enough for long, fast routes, scaled to the machine's memory.

    Buffer ceiling ~ bandwidth x round-trip time: 1 Gbit/s over 250 ms needs ~32 MB per connection.
    Small VPSes get smaller ceilings so a burst of connections cannot exhaust memory.
    """
    mem_mb = mem_mb or mem_total_mb()
    if mem_mb >= 3500:
        cap = 64 << 20
    elif mem_mb >= 1800:
        cap = 32 << 20
    elif mem_mb >= 900:
        cap = 16 << 20
    else:
        cap = 8 << 20
    pages = mem_mb * 256                      # 4 KiB pages in RAM
    lines = {
        'net.core.default_qdisc': 'fq',
        'net.ipv4.tcp_congestion_control': 'bbr',
        'net.core.rmem_max': cap, 'net.core.wmem_max': cap,
        'net.core.rmem_default': 1 << 20, 'net.core.wmem_default': 1 << 20,
        'net.ipv4.tcp_rmem': '4096 131072 %d' % cap,
        'net.ipv4.tcp_wmem': '4096 65536 %d' % cap,
        # Total TCP memory: at most ~1/4 of RAM under pressure.
        'net.ipv4.tcp_mem': '%d %d %d' % (pages // 16, pages // 8, pages // 4),
        'net.ipv4.udp_mem': '%d %d %d' % (pages // 16, pages // 8, pages // 4),
        'net.ipv4.tcp_notsent_lowat': 131072,   # less queueing delay inside the server
        'net.ipv4.tcp_slow_start_after_idle': 0,
        'net.ipv4.tcp_mtu_probing': 1,          # survive paths that drop large packets
        'net.ipv4.tcp_fastopen': 3,
        'net.ipv4.tcp_fin_timeout': 15,
        'net.ipv4.tcp_keepalive_time': 300, 'net.ipv4.tcp_keepalive_intvl': 30, 'net.ipv4.tcp_keepalive_probes': 5,
        'net.ipv4.tcp_max_syn_backlog': 8192, 'net.core.somaxconn': 8192,
        'net.core.netdev_max_backlog': 16384,
        'net.ipv4.ip_local_port_range': '10240 65000',
        'net.ipv4.tcp_tw_reuse': 1,
        'fs.file-max': 1048576,
    }
    head = '# Written by vps2vpn. Delete this file and reboot to undo.\n'
    return head + ''.join('%s = %s\n' % kv for kv in lines.items())


def tune_network(enabled=True):
    if not paths.LIVE:
        return 'skipped (not running as root on Linux)'
    if not enabled:
        if os.path.exists(paths.SYSCTL_FILE):
            os.unlink(paths.SYSCTL_FILE)
        return 'off'
    run(['modprobe', 'tcp_bbr'])
    paths.write_atomic(paths.SYSCTL_FILE, sysctl_text(), 0o644)
    r = run(['sysctl', '-p', paths.SYSCTL_FILE])
    return 'ok' if r.returncode == 0 else 'partial: ' + (r.stderr or '')[-200:]


def bbr_active():
    try:
        with open('/proc/sys/net/ipv4/tcp_congestion_control') as f:
            return f.read().strip() == 'bbr'
    except OSError:
        return None


# --- UDP port hopping for Hysteria 2 ----------------------------------------------
NFT_TABLE = 'vps2vpn'


def parse_range(text):
    m = re.fullmatch(r'\s*(\d{1,5})\s*[-:]\s*(\d{1,5})\s*', text or '')
    if not m:
        raise ValueError('port range must look like 20000-40000')
    a, b = int(m.group(1)), int(m.group(2))
    if not (1024 <= a < b <= 65535):
        raise ValueError('port range must be inside 1024-65535')
    return a, b


def nft_rules(s):
    a, b = parse_range(s['hy2_hop_range'])
    return ('table inet %s {\n'
            ' chain prerouting {\n'
            '  type nat hook prerouting priority dstnat; policy accept;\n'
            '  udp dport %d-%d redirect to :%d\n'
            ' }\n'
            '}\n') % (NFT_TABLE, a, b, s['hy2_port'])


def port_hopping(s):
    """Clients pick random UDP ports in the range; the kernel sends them all to Hysteria."""
    if not paths.LIVE or not shutil.which('nft'):
        return None
    run(['nft', 'delete', 'table', 'inet', NFT_TABLE])
    if not (s['hy2_enabled'] and s['hy2_hop']):
        return 'off'
    r = subprocess.run(['nft', '-f', '-'], input=nft_rules(s), capture_output=True, text=True)
    return 'ok' if r.returncode == 0 else 'failed: ' + r.stderr[-200:]


# --- host firewall (only if one is already active; we never enable one) ----------
def needed_ports(s):
    out = [('tcp', str(s['panel_port'])), ('tcp', '80')]
    if s['reality_enabled']:
        out.append(('tcp', str(s['reality_port'])))
    if s['hy2_enabled']:
        out.append(('udp', str(s['hy2_port'])))
        if s['hy2_hop']:
            a, b = parse_range(s['hy2_hop_range'])
            out.append(('udp', '%d-%d' % (a, b)))
    if s.get('tuic_enabled'):
        out.append(('udp', str(s['tuic_port'])))
    return out


def open_firewall(s):
    if not paths.LIVE:
        return []
    done = []
    if shutil.which('ufw') and 'Status: active' in run(['ufw', 'status']).stdout:
        for proto, port in needed_ports(s):
            run(['ufw', 'allow', '%s/%s' % (port.replace('-', ':'), proto)])
            done.append('ufw %s/%s' % (port, proto))
    elif shutil.which('firewall-cmd') and run(['firewall-cmd', '--state']).stdout.strip() == 'running':
        for proto, port in needed_ports(s):
            run(['firewall-cmd', '--permanent', '--add-port=%s/%s' % (port, proto)])
            done.append('firewalld %s/%s' % (port, proto))
        run(['firewall-cmd', '--reload'])
    return done


def port_free(proto, port):
    """True if nothing else listens on this port (checked by binding it ourselves)."""
    kind = socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM
    for f in (socket.AF_INET, socket.AF_INET6):
        try:
            sk = socket.socket(f, kind)
        except OSError:
            continue                                  # this address family is not available here
        try:
            if proto == 'tcp' and os.name != 'nt':    # ignore TIME_WAIT leftovers (Windows means something else by it)
                sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if f == socket.AF_INET6:
                sk.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sk.bind(('::' if f == socket.AF_INET6 else '0.0.0.0', port))
        except OSError as e:
            if f == socket.AF_INET6 and e.errno in (97, 99, 10047, 10049):    # IPv6 switched off on this machine
                continue
            return False
        finally:
            sk.close()
    return True


def port_owner(proto, port):
    """Name of the program holding a port, for friendlier messages (Linux only)."""
    r = run(['ss', '-H', '-lnp' + ('u' if proto == 'udp' else 't'), 'sport = :%d' % port])
    m = re.search(r'users:\(\("([^"]+)"', r.stdout or '')
    return m.group(1) if m else ''


# --- encrypted DNS ------------------------------------------------------------------
DOH = (('1.1.1.1', 'cloudflare-dns.com'), ('8.8.8.8', 'dns.google'), ('9.9.9.9', 'dns.quad9.net'))
_doh_cache = {}


def doh_servers(max_age=86400):
    """Encrypted DNS resolvers this server can actually reach (some hosts block them). Probed once a day:
    a resolver that does not answer would add seconds to every new connection."""
    if _doh_cache and time.time() - _doh_cache['at'] < max_age:
        return _doh_cache['ok']
    ok = []
    for ip, name in DOH:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=name):
                    ok.append((ip, name))
        except OSError:
            continue
    _doh_cache.update(at=time.time(), ok=ok)
    return ok


# --- addresses ---------------------------------------------------------------------
def public_ip(v6=False):
    """Ask Cloudflare's trace endpoint which address we come from (cloud servers are often behind NAT)."""
    host = '[2606:4700:4700::1111]' if v6 else '1.1.1.1'
    for url in ('https://%s/cdn-cgi/trace' % host, 'https://%s/cdn-cgi/trace' % ('one.one.one.one')):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False if url.startswith('https://1') or url.startswith('https://[') else True
            ctx.verify_mode = ssl.CERT_REQUIRED if ctx.check_hostname else ssl.CERT_NONE
            text = urllib.request.urlopen(url, timeout=6, context=ctx).read().decode()
            ip = re.search(r'^ip=(.+)$', text, re.M).group(1).strip()
            if (':' in ip) == v6:
                return ip
        except (OSError, AttributeError, ValueError):
            continue
    return ''


# --- REALITY camouflage site check ------------------------------------------------
# Big sites that speak TLS 1.3 + HTTP/2. Xray warns against microsoft.com, apple.com and icloud.com
# because so many servers already use them.
GOOD_TARGETS = ['www.amd.com', 'www.nvidia.com', 'www.samsung.com', 'www.tesla.com', 'www.oracle.com',
                'www.cisco.com', 'www.intel.com', 'www.lenovo.com', 'www.asus.com', 'www.sony.com',
                'www.yahoo.co.jp', 'addons.mozilla.org']


def check_target(host, timeout=5):
    """REALITY needs a site that speaks TLS 1.3 and HTTP/2 and answers fast from this server."""
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                ok = tls.version() == 'TLSv1.3' and tls.selected_alpn_protocol() == 'h2'
                return {'host': host, 'ok': ok, 'ms': int((time.time() - t0) * 1000),
                        'tls': tls.version(), 'alpn': tls.selected_alpn_protocol()}
    except (OSError, ssl.SSLError) as e:
        return {'host': host, 'ok': False, 'ms': None, 'error': str(e)[:120]}


def best_target():
    """Pick the fastest suitable camouflage site from this server."""
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(8) as ex:
        res = list(ex.map(check_target, GOOD_TARGETS))
    good = sorted((r for r in res if r['ok']), key=lambda r: r['ms'])
    return (good[0]['host'] if good else GOOD_TARGETS[0]), res


# --- health -----------------------------------------------------------------------
_last_net = {}


def health():
    out = {'time': int(time.time())}
    try:
        with open('/proc/loadavg') as f:
            out['load'] = float(f.read().split()[0])
        out['cpus'] = os.cpu_count()
        with open('/proc/meminfo') as f:
            mi = dict((k, int(v.split()[0])) for k, v in (l.split(':', 1) for l in f if ':' in l))
        out['mem_total'] = mi['MemTotal'] * 1024
        out['mem_used'] = (mi['MemTotal'] - mi.get('MemAvailable', mi['MemFree'])) * 1024
        with open('/proc/uptime') as f:
            out['uptime'] = int(float(f.read().split()[0]))
        rx = tx = 0
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, data = line.split(':', 1)
                if name.strip() == 'lo':
                    continue
                v = data.split()
                rx += int(v[0])
                tx += int(v[8])
        now = time.time()
        if _last_net:
            dt = max(now - _last_net['t'], 0.001)
            out['rx_rate'] = int((rx - _last_net['rx']) / dt)
            out['tx_rate'] = int((tx - _last_net['tx']) / dt)
        _last_net.update(t=now, rx=rx, tx=tx)
        out['rx_total'], out['tx_total'] = rx, tx
        st = os.statvfs('/')
        out['disk_total'] = st.f_blocks * st.f_frsize
        out['disk_used'] = (st.f_blocks - st.f_bfree) * st.f_frsize
    except (OSError, ValueError, KeyError, AttributeError):
        pass
    out['bbr'] = bbr_active()
    return out


def os_info():
    try:
        with open('/etc/os-release') as f:
            m = re.search(r'^PRETTY_NAME="?([^"\n]+)', f.read(), re.M)
            return m.group(1) if m else ''
    except OSError:
        return ''


def dump(obj):
    return json.dumps(obj, ensure_ascii=False)


# Cloud firewalls live in the provider's web console, outside the server, so the installer cannot open them.
# Name the provider and the exact place, which beats a bare list of port numbers.
CLOUD_HINTS = {
    'lightsail': ('AWS Lightsail', 'Lightsail console > your instance > Networking > IPv4 firewall > Add rule > '
                  'Application "All protocols" > Create. 控制台 > 点实例 > 联网 > IPv4 防火墙 > 添加规则 > '
                  '应用程序选「所有协议」> 创建。'),
    'ec2': ('AWS EC2', 'EC2 console > Instances > your instance > Security > the security group > Edit inbound rules > '
            'Add rule "All traffic", source 0.0.0.0/0 > Save. 实例 > 安全 > 安全组 > 编辑入站规则 > 添加「所有流量」'
            '来源 0.0.0.0/0 > 保存。'),
    'oracle': ('Oracle Cloud', 'Instance > Subnet > Security List > Add Ingress Rules: source 0.0.0.0/0, IP protocol "All". '
               '实例 > 子网 > 安全列表 > 添加入站规则：来源 0.0.0.0/0，协议选「所有协议」。'),
    'gcp': ('Google Cloud', 'VPC network > Firewall > Create firewall rule: targets "All instances", source 0.0.0.0/0, '
            '"Allow all". VPC 网络 > 防火墙 > 创建规则：所有实例，来源 0.0.0.0/0，全部允许。'),
    'azure': ('Azure', 'Virtual machine > Networking > Add inbound port rule: Any port, Any protocol, Allow. '
              '虚拟机 > 网络 > 添加入站端口规则：任意端口、任意协议、允许。'),
    'aliyun': ('Alibaba Cloud', '实例 > 安全组 > 配置规则 > 入方向 > 手动添加：协议「全部」，来源 0.0.0.0/0（轻量服务器：防火墙 > 添加规则）。'),
    'tencent': ('Tencent Cloud', '实例 > 安全组 > 修改规则 > 入站规则 > 添加：来源 0.0.0.0/0，协议端口 ALL（轻量服务器：防火墙 > 添加规则 > 全部）。'),
}


def cloud_provider():
    """Best guess at the hosting provider from DMI data (no network calls). Returns a CLOUD_HINTS key or ''."""
    def read(name):
        try:
            with open('/sys/class/dmi/id/' + name) as f:
                return f.read().strip().lower()
        except OSError:
            return ''
    dmi = ' '.join(read(n) for n in ('sys_vendor', 'product_name', 'bios_vendor', 'board_vendor', 'chassis_asset_tag'))
    if 'amazon' in dmi or read('product_uuid').startswith('ec2') or read('bios_version').find('amazon') >= 0:
        # Lightsail instances sit in AWS's own 172.26.0.0/16 network
        return 'lightsail' if socket.gethostname().startswith('ip-172-26-') else 'ec2'
    for key, words in (('oracle', ('oraclecloud', 'oracle')), ('gcp', ('google',)), ('aliyun', ('alibaba', 'aliyun')),
                       ('tencent', ('tencent',))):
        if any(w in dmi for w in words):
            return key
    if 'microsoft' in dmi and '7783-7084-3265-9085-8269-3286-77' in dmi:     # Azure's chassis asset tag
        return 'azure'
    return ''

