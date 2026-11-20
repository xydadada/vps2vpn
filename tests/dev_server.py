"""Run the panel locally for UI work (no root, nothing installed, cores not started).

    python tests/dev_server.py [port]

Prints the setup link. Data lives in ./.dev (delete it to start over).
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('VPS2VPN_ROOT', os.path.join(HERE, '.dev'))
os.environ['VPS2VPN_DEV'] = '1'
sys.path.insert(0, HERE)

from vps2vpn import certs, db, paths, secure, web  # noqa: E402

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
paths.ensure_dirs()
s = db.ensure_secrets()
db.set_settings(panel_port=port, public_host=s['public_host'] or '127.0.0.1', panel_path='dev', member_path='member')
if not db.settings()['setup_done'] and not web.setup_token():
    with open(web.SETUP_TOKEN_FILE, 'w') as f:
        f.write('devsetup')
certs.ensure_self_signed(db.settings()['public_host'])
print('panel: http://localhost:%d/dev/?setup=devsetup  (dev mode: plain HTTP allowed on loopback only)' % port, flush=True)
web.serve(port, host='127.0.0.1')
