"""Run the actual settings form and validate its submitted values."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from tests import test_unit as tu
from vps2vpn import clock, db, web


SOURCE = (Path(__file__).resolve().parents[1] / 'vps2vpn/static/app.js').read_text(encoding='utf-8')
FORM = SOURCE[SOURCE.index('function drawSettings()'):SOURCE.index('function clientPanel(')]


@unittest.skipUnless(shutil.which('node'), 'needs Node.js')
class SettingsTimeZone(tu.Base):
    def submit_form(self, settings):
        script = r'''
const fs = require('node:fs');
const S = {view:'settings',data:{settings:JSON.parse(fs.readFileSync(0,'utf8')),cert:{}},viewSeq:1};
let L = 'en', submitted;
const nodes = [];
function h(tag, attrs, ...children) {
  const node = {tag, dataset:{}, style:{}, type:attrs?.type || '',
    checked:!!attrs?.checked, className:attrs?.class || '',
    children:children.flat(Infinity).filter(x=>x!=null && x!==false)};
  let value = String(attrs?.value ?? '');
  Object.defineProperty(node, 'value', {
    get:()=>value,
    set:v=>{value=tag==='select' && !node.children.some(o=>o.value===String(v)) ? '' : String(v);}
  });
  nodes.push(node);
  return node;
}
const t = key=>key, icon = name=>h('i',null,name);
const field = (...args)=>h('label',null,...args);
const check = field, panel = field, tip = field, chip = field;
const clientPanel = ()=>h('div'), certStatus = ()=>null;
const $ = ()=>({replaceChildren(){}});
const numOrNull = v=>v==='' ? null : Number(v);
const toast = ()=>{}, err = error=>{throw error;};
const api = async (path, body)=>{submitted=body;return {};};
const load = async ()=>{}, renderShell = async ()=>{};
'''
        script += FORM + r'''
(async()=>{
  drawSettings();
  nodes.find(n=>n.dataset.k==='node_name').value='Changed name';
  await nodes.find(n=>n.tag==='button' && n.className==='btn primary').onclick();
  if (!submitted) throw Error('settings were not submitted');
  process.stdout.write(JSON.stringify(submitted));
})().catch(error=>{console.error(error);process.exit(1);});
'''
        result = subprocess.run(['node', '-e', script], input=json.dumps(settings),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_unrelated_save_preserves_each_supported_timezone(self):
        for zone in ('UTC+5', 'UTC-7', 'UTC-9', 'UTC', 'UTC+8', 'Asia/Kolkata', ''):
            if zone and clock.valid(zone) is None:
                continue                                    # IANA names need zoneinfo (Python 3.9+ with tzdata)
            with self.subTest(zone=zone):
                db.set_settings(time_zone=zone)
                settings = db.settings()
                body = self.submit_form(settings)
                changes = web.validate_settings(body, settings)
                self.assertIsInstance(changes, dict, changes)
                db.set_settings(**changes)
                self.assertEqual(db.settings()['node_name'], 'Changed name')
                self.assertEqual(db.settings()['time_zone'], zone)

    def test_note_only_save_preserves_expiry_but_an_edited_date_is_applied(self):
        db.set_settings(time_zone='UTC+5')
        original_expiry = 1898559000  # 2030-03-01 01:30 UTC, deliberately not a day boundary
        uid = db.add_user('Expiry round trip', 0, expire_at=original_expiry)
        user = db.user(uid)
        user['expire_day'] = clock.date_of(original_expiry)
        start = SOURCE.index('  form.onsubmit = async e => {', SOURCE.index('function editUser('))
        handler = SOURCE[start:SOURCE.index("  $('drawer').replaceChildren", start)]
        for date in (user['expire_day'], '2030-03-02'):
            with self.subTest(date=date):
                script = r'''
const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const u=input.user, isNew=false, form={}, save={}, S={view:'home'};
const f=Object.fromEntries(Object.entries({name:u.name,quota:0,reset:0,note:'Changed note',
  ips:0,mode:'date',exp:input.date,first:0,speed:0,slow:0}).map(([k,value])=>[k,{value:String(value)}]));
const pick={value:()=>''}, load=async()=>{}, toast=()=>{}, t=k=>k, closeDrawer=()=>{};
const err=e=>{throw e;}, api=async(path,body)=>{process.stdout.write(JSON.stringify(body));return {};};
'''
                script += handler + r'''
form.onsubmit({preventDefault(){}}).catch(e=>{console.error(e);process.exit(1);});
'''
                result = subprocess.run(['node', '-e', script],
                                        input=json.dumps({'user': user, 'date': date}),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                changes = web.user_fields(json.loads(result.stdout))
                self.assertIsInstance(changes, dict, changes)
                db.update_user(uid, **changes)
                expected = original_expiry if date == user['expire_day'] else clock.day_end(date)
                self.assertEqual(db.user(uid)['expire_at'], expected)
                self.assertEqual(db.user(uid)['note'], 'Changed note')
