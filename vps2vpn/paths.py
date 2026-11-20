"""Where everything lives. Set VPS2VPN_ROOT to run the panel somewhere else (tests, development)."""
import os
import sys
import tempfile

_root = os.environ.get('VPS2VPN_ROOT', '')

ETC = _root + '/etc/vps2vpn'          # configuration, keys, certificates (root only)
VAR = _root + '/var/lib/vps2vpn'      # database, rule-set mirror
APP = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(APP, 'static')

DB = VAR + '/vps2vpn.db'
RULES = VAR + '/rules'
BACKUPS = VAR + '/backups'
CLIENT = VAR + '/client'               # vps2vpn app installers offered to members (vps2vpn-<ver>-<platform>.<ext>)
XRAY_CONFIG = ETC + '/xray.json'
HY2_CONFIG = ETC + '/hysteria.json'
TUIC_CONFIG = ETC + '/tuic.json'
NFT_FILE = ETC + '/nft-hop.nft'        # port-hopping rules, re-loaded at boot by NFT_UNIT
NFT_UNIT = _root + '/etc/systemd/system/vps2vpn-nft.service'
CERT_DIR = ETC + '/cert'
SELF_CRT = CERT_DIR + '/self.crt'
SELF_KEY = CERT_DIR + '/self.key'
ACME_CRT = CERT_DIR + '/acme.crt'
ACME_KEY = CERT_DIR + '/acme.key'
ACME_ACCOUNT = CERT_DIR + '/acme-account.key'
SYSCTL_FILE = _root + '/etc/sysctl.d/99-vps2vpn.conf'
MODULES_FILE = _root + '/etc/modules-load.d/vps2vpn.conf'

XRAY_BIN = os.environ.get('VPS2VPN_XRAY', '/usr/local/lib/vps2vpn/xray')
HY2_BIN = os.environ.get('VPS2VPN_HYSTERIA', '/usr/local/lib/vps2vpn/hysteria')
SINGBOX_BIN = os.environ.get('VPS2VPN_SINGBOX', '/usr/local/lib/vps2vpn/sing-box')

DEV = os.environ.get('VPS2VPN_DEV') == '1'     # local development: panel also answers plain HTTP on loopback

# Real system changes (systemctl, sysctl, nft) only on Linux as root and not in dev mode.
LIVE = sys.platform.startswith('linux') and hasattr(os, 'geteuid') and os.geteuid() == 0 \
    and not _root and os.environ.get('VPS2VPN_DEV') != '1'


def ensure_dirs():
    # ETC: cores (group vps2vpn) read their configs and the TLS key; VAR holds the database (root only).
    for d, mode in ((ETC, 0o750), (CERT_DIR, 0o750), (VAR, 0o700), (RULES, 0o755), (CLIENT, 0o755)):
        os.makedirs(d, exist_ok=True)
        if LIVE:
            os.chmod(d, mode)
            if d in (ETC, CERT_DIR):
                import grp
                try:
                    os.chown(d, 0, grp.getgrnam('vps2vpn').gr_gid)
                except KeyError:
                    pass


def write_atomic(path, data, mode=0o600, group=None):
    """Write a file so readers never see a half-written version."""
    if isinstance(data, str):
        data = data.encode()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.tmp', dir=parent)
    try:
        try:
            os.fchmod(fd, mode)
        except AttributeError:
            os.chmod(tmp, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if group and LIVE:
            import grp
            try:
                os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
            except KeyError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
