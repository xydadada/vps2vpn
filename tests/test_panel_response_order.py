"""Exercise production panel requests with deliberately reordered promises."""
from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / 'vps2vpn/static/app.js').read_text(encoding='utf-8')


def section(start, end):
    return SOURCE[SOURCE.index(start):SOURCE.index(end, SOURCE.index(start))]


@unittest.skipUnless(shutil.which('node'), 'needs Node.js')
class PanelResponseOrder(unittest.TestCase):
    def run_node(self, script):
        result = subprocess.run(['node', '-e', script], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_js(self, code):
        prelude = '''
const assert = require('node:assert/strict');
const S = {data:null, days:[], charts:{}, view:'settings', viewSeq:1,
  refreshSeq:0, refreshing:false, loadSeq:0, daysSeq:0, sysSeq:0};
let L = 'en', redraws = 0;
const KT = {locale:'en-US'};
const Clock = {seen() {}};
const setLang = l => { L = l; };
const t = key => key, toast = () => {}, err = () => {};
const elements = {
  view:{}, syncInfo:{textContent:''},
  livePill:{stale:false, classList:{
    add() {elements.livePill.stale=true;}, remove() {elements.livePill.stale=false;}
  }}
};
const $ = id => elements[id];
const document = {querySelector:() => null};
const updateReqBadges = () => {}, updateHome = () => {}, drawUsers = () => {};
const go = () => {redraws++;};
const pending = [];
const api = path => new Promise((resolve,reject) => pending.push({path,resolve,reject}));
const state = name => ({name, settings:{language:'en'}, health:{time:1}});
const settle = async () => {for(let i=0;i<8;i++) await Promise.resolve();};
'''
        functions = section('async function saveSettings(', 'async function renderShell(')
        functions += section('async function refresh(', '/* ---------------- overview')
        functions += section('async function loadSys(', 'function updateHome(')
        self.run_node(prelude + functions +
                      '\n(async()=>{' + code + '})().catch(e=>{console.error(e);process.exit(1);});')

    def test_older_state_reply_cannot_overwrite_newer_refresh(self):
        self.run_js('''
const old = load(), fresh = load();
pending[1].resolve(state('fresh')); await fresh;
pending[0].resolve(state('old')); await old;
assert.equal(S.data.name, 'fresh');
''')

    def test_older_traffic_failure_cannot_clear_newer_history(self):
        self.run_js('''
const old = loadDays(), fresh = loadDays();
pending[1].resolve({days:[{day:'2030-01-01',up:1,down:2}]}); await fresh;
pending[0].reject(Error('old failure')); await old;
assert.equal(S.days.length, 1);
''')

    def test_old_refresh_error_cannot_mark_newer_success_stale(self):
        self.run_js('''
const old = refresh(false), fresh = refresh(true);
pending[1].resolve(state('fresh')); await settle();
pending[2].resolve({days:[]}); await fresh;
const status = elements.syncInfo.textContent;
pending[0].reject(Error('old 503')); await old;
assert.equal(elements.livePill.stale, false);
assert.equal(elements.syncInfo.textContent, status);
''')

    def test_settings_save_does_not_redraw_after_navigation(self):
        self.run_js('''
const saved = saveSettings({node_name:'new'}, () => {redraws++;});
S.view = 'users'; S.viewSeq++;
pending[0].resolve({}); await settle();
pending[1].resolve(state('fresh')); await saved;
assert.equal(redraws, 0);
assert.equal(S.data.name, 'fresh');
''')

    def test_older_system_history_cannot_overwrite_newer_sample(self):
        self.run_js('''
const old = loadSys(true), fresh = loadSys(true);
pending[1].resolve({points:[[600,2,3,4,5]]}); await fresh;
pending[0].resolve({points:[[300,8,9,10,11]]}); await old;
assert.equal(S.sys[0].t, 750);
''')

    def test_settings_button_preserves_the_page_selected_while_saving(self):
        save = section('  saveBtn.onclick = async () => {', "  $('view').replaceChildren(h('section', {class: 'page'},\n    panel(t('s_proto')")
        self.run_js('''
const seq = S.viewSeq, saveBtn = {}, inputs = [
  {dataset:{k:'reality_enabled'},type:'checkbox',checked:true}
];
const drawSettings = () => {redraws++;}, renderShell = async () => {redraws++;};
''' + save + '''
const saving = saveBtn.onclick();
S.view='users'; S.viewSeq++;
pending[0].resolve({}); await settle();
pending[1].resolve(state('fresh')); await saving;
assert.equal(redraws, 0);
''')

    def test_an_old_unauthorized_reply_cannot_sign_out_a_new_session(self):
        api = section('async function api(', 'const err =')
        self.run_node('''
const assert=require('node:assert/strict'), S={sessionSeq:1}, KT={};
let resolve, logins=0;
const fetch=()=>new Promise(r=>{resolve=r;});
const renderLogin=()=>{logins++;S.sessionSeq++;};
''' + api + '''
(async()=>{
  const old=api('state').catch(e=>e.message);
  S.sessionSeq++;
  resolve({status:401,ok:false,json:async()=>({})});
  assert.equal(await old,'login');
  assert.equal(logins,0);
  const current=api('state').catch(e=>e.message);
  resolve({status:401,ok:false,json:async()=>({})});
  assert.equal(await current,'login');
  assert.equal(logins,1);
})().catch(e=>{console.error(e);process.exit(1);});
''')
