"""A completed mutation must not draw over the page opened while it waited."""
from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / 'vps2vpn/static/app.js').read_text(encoding='utf-8')


def section(start, end):
    offset = SOURCE.index(start)
    return SOURCE[offset:SOURCE.index(end, offset)]


DRAW = {
    'users': section('function drawUsers()', 'function batchAdd()'),
    'members': section('async function drawMembers()', '/* ---------------- servers:'),
    'servers': section('async function drawServers()', '/* ---------------- monitor:'),
    'monitor': section('async function drawMonitor()', '/* ---------------- settings'),
    'settings': section('function drawSettings()', 'function clientPanel('),
    'system': section('function drawSystem()', '\nboot();'),
}
CALLBACKS = {
    'users': (section('async function bulk(', 'function usageBar('), "bulk('disable')"),
    'members': (section('  const fbAct =', '  const fbDetail ='), "fbAct({id:1},'done')"),
    'servers': ('const add={},code={value:"REDACTED"},name={value:"REDACTED"};\n' +
                section('  add.onclick =', '  const act = async (btn, id,'), 'add.onclick()'),
    'monitor': ('const scan={};\n' + section('  scan.onclick =', '  const sep ='), 'scan.onclick()'),
    'settings': (section('async function changePort(', '/* ---------------- users'),
                 "changePort('reality','REDACTED',drawSettings)"),
    'system': ('const tgOffBtn={};\n' + section('  tgOffBtn.onclick =', '  const tgConnBtn ='),
               'tgOffBtn.onclick()'),
}


@unittest.skipUnless(shutil.which('node'), 'needs Node.js')
class PanelPageOwnership(unittest.TestCase):
    def run_js(self, code):
        result = subprocess.run(['node', '-e', code], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'done', 'the asynchronous scenario must finish')

    def test_completed_mutations_do_not_touch_the_page_selected_while_waiting(self):
        for page, (callback, invoke) in CALLBACKS.items():
            for closed in (False, True):
                with self.subTest(page=page, closed=closed):
                    prelude = '''
const assert=require('node:assert/strict');
const S={view:PAGE,viewSeq:1,data:{settings:{}},sel:new Set([1])};
let created=0,view={replaceChildren(){created++;}};
const $=id=>id==='view'?view:null;
const h=()=>{created++;throw Error('stale redraw touched the selected page');};
const pending=[],api=()=>new Promise(resolve=>pending.push(resolve));
const errors=[],load=async()=>{},toast=()=>{},err=e=>errors.push(e),updateReqBadges=()=>{};
const icon=()=>({});
const confirmBox=async()=>true;
const t=key=>key==='change_port_q'||key==='port_changed'?value=>value:key;
const settle=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
'''.replace('PAGE', repr(page))
                    self.run_js(prelude + DRAW[page] + callback + '''
(async()=>{
  const action=INVOKE;
  await settle();
  assert.equal(pending.length,1,'the actual mutation must be waiting');
  if (CLOSED) view=null;
  else S.view=PAGE==='settings'?'users':'settings';
  S.viewSeq++;
  pending[0]({done:1});
  await action; await settle();
  assert.equal(created,0,'the old mutation must leave the selected page intact');
  assert.deepEqual(errors,[],'no stale page errors are reported after the mutation succeeds');
  process.stdout.write('done');
})().catch(e=>{console.error(e);process.exit(1);});
'''.replace('INVOKE', invoke).replace('CLOSED', str(closed).lower()).replace('PAGE', repr(page)))

    def test_the_current_async_page_still_loads_and_shows_request_errors(self):
        for page, paths in (('members', ['invites', 'requests', 'feedback']),
                            ('servers', ['servers']), ('monitor', ['monitor', 'abuse'])):
            with self.subTest(page=page):
                name = 'draw' + page.title()
                self.run_js('''
const assert=require('node:assert/strict'),S={view:PAGE,viewSeq:1,data:{settings:{}}};
const calls=[],pending=[];let drawings=0;
const $=()=>({replaceChildren(){drawings++;}}),h=()=>({});
const api=path=>{calls.push(path);return new Promise((_,reject)=>pending.push(reject));};
const retryBox=()=>({}),err=()=>{};
'''.replace('PAGE', repr(page)) + DRAW[page] + '''
(async()=>{
  const drawing=NAME();
  assert.equal(drawings,1,'current page shows the loading state');
  assert.deepEqual(calls,PATHS);
  pending.forEach(reject=>reject(Error('synthetic unavailable response')));
  await drawing;
  assert.equal(drawings,2,'current page keeps its retry state');
  process.stdout.write('done');
})().catch(e=>{console.error(e);process.exit(1);});
'''.replace('NAME', name).replace('PATHS', repr(paths)))


if __name__ == '__main__':
    unittest.main()
