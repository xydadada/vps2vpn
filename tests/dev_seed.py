"""Fill the local development panel (./.dev) with sample data for UI work.

    python tests/dev_seed.py

Writes a fresh admin password and a member password to .dev/dev-logins.txt (local test accounts only).
"""
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('VPS2VPN_ROOT', os.path.join(HERE, '.dev'))
os.environ['VPS2VPN_DEV'] = '1'
sys.path.insert(0, HERE)

from vps2vpn import db, members, paths, secure  # noqa: E402

paths.ensure_dirs()
db.ensure_secrets()
admin_pw, member_pw = secure.token(12), secure.token(12)
db.set_settings(setup_done=True, admin_user='admin', admin_hash=secure.hash_password(admin_pw), member_path='member',
                panel_path='dev', server_cap_gb=2000,
                server_month={'period': time.strftime('%Y-%m-01'), 'rx': 310e9, 'tx': 1270e9, 'at': int(time.time())})
random.seed(7)
names = [('小明', 200, 1), ('Alice', 100, 15), ('爸妈', 0, 0), ('Bob', 50, 1)]
ids = {}
for name, quota, reset in names:
    u = db.user_by_name(name)
    ids[name] = u['id'] if u else db.add_user(name, quota, 0, reset, '')
db.update_user(ids['小明'], login_hash=secure.hash_password(member_pw), note='家里网络')
db.update_user(ids['Bob'], expire_at=int(time.time() + 9 * 86400))
now = time.time()
if not db.user_traffic(ids['小明']):
    for name, uid in ids.items():
        for d in range(30):
            if random.random() < .85:
                down = int(random.uniform(.2, 6) * 1e9 * (1.6 if name == '小明' else 1))
                db.add_traffic(uid, int(down * .06), down, now=now - d * 86400)
if not db.invites():
    rec = members.create_invite('member', 10, 7, max_uses=2, inviter=ids['小明'], note='同事')
    members.register(rec['code'], '同事小王', secure.token(12))
    members.create_invite('admin', 100, 14, max_uses=5, expire_days=90, note='新朋友')
    members.request_more(ids['Bob'], 30, '这个月要考试，查资料多')
open(os.path.join(os.environ['VPS2VPN_ROOT'], 'dev-logins.txt'), 'w', encoding='utf-8').write(
    'admin / %s\n小明 (member centre /member/) / %s\n' % (admin_pw, member_pw))
print('seeded; logins in .dev/dev-logins.txt')
