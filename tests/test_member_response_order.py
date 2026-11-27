"""Drive the production member renderer with deliberately reordered network replies."""
from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / 'vps2vpn/static/member.js').read_text(encoding='utf-8')


@unittest.skipUnless(shutil.which('node'), 'needs Node.js')
class MemberResponseOrder(unittest.TestCase):
    def run_js(self, code):
        source = SOURCE[:SOURCE.index('/* ---------- sign in')]
        source += SOURCE[SOURCE.index('function renderLogin('):SOURCE.index('function requestsPanel(')]
        prelude = '''
const assert = require('node:assert/strict');
const navigator = {language:'en',userAgent:''}, KT = {net:'network failed',failed:'failed'};
const frames = [], pending = [];
const document = {body:{replaceChildren(node) {frames.push(node);}}};
const h = (tag, attrs, ...children) => ({tag,attrs,children,value:attrs?.value || '',firstChild:children[0],focus() {}});
const icon = key => key, fmt = {bytes:String,pct:String,time:String};
const Theme = {mount() {}}, Ring = class {set() {}}, DayBars = class {set() {}};
const frame = node => document.body.replaceChildren(node);
const fetch = () => new Promise((resolve,reject) => pending.push({resolve,reject}));
const answer = (index, name, status=200) => pending[index].resolve({status,ok:status===200,
  json:async()=>({name,used_up:0,used_down:0,quota_gb:0,enabled:true,import:{},history:[]})});
const history = {replaceState() {}}, location = {pathname:'/member/'}, window = {scrollTo() {}};
'''
        result = subprocess.run(['node', '-e', prelude + source + '''
M.hello = {mode:'link'};
(async()=>{
''' + code + '\n})().then(()=>process.stdout.write("done")).catch(e=>{console.error(e);process.exit(1);});'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'done', 'the async scenario must finish before Node exits')

    def test_newest_home_reply_wins(self):
        self.run_js('''
const old = renderHome(), fresh = renderHome();
answer(1,'fresh'); await fresh;
answer(0,'old'); await old;
assert.equal(M.me.name,'fresh');
assert.equal(frames.length,1);
''')

    def test_a_pending_home_cannot_restore_signed_out_data(self):
        self.run_js('''
M.me = {name:'previous'};
const old = renderHome();
renderLogin();
assert.equal(M.me,null);
answer(0,'old'); await old;
assert.equal(M.me,null);
assert.equal(frames.length,1);
''')

    def test_old_network_failure_does_not_replace_a_new_home(self):
        self.run_js('''
const old = renderHome(), fresh = renderHome();
answer(1,'fresh'); await fresh;
pending[0].reject(Error('offline')); await old;
assert.equal(M.me.name,'fresh');
assert.equal(frames.length,1);
''')

    def test_old_unauthorized_reply_cannot_sign_out_a_new_view(self):
        self.run_js('''
const old = renderHome();
renderLogin();
const fresh = renderHome();
answer(1,'fresh'); await fresh;
answer(0,'old',401); await old;
assert.equal(M.me.name,'fresh');
assert.equal(frames.length,2);
const current = renderHome();
answer(2,'expired',401); await current;
assert.equal(M.me,null);
assert.equal(frames.length,3);
''')

    def test_old_login_completion_does_not_leave_a_new_registration_form(self):
        self.run_js('''
renderLogin();
const oldForm = frames[0];
const loggingIn = oldForm.onsubmit({preventDefault() {}});
renderLogin('');
answer(0,'signed in');
for(let i=0;i<8;i++) await Promise.resolve();
assert.equal(pending.length,1);
assert.equal(frames.length,2);
await loggingIn;
''')
