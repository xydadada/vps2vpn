'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function frontend() {
  const context = vm.createContext({
    navigator: {language: 'en'},
    document: {
      hidden: false, documentElement: {removeAttribute() {}, setAttribute() {}},
      addEventListener() {}, querySelectorAll: () => [], querySelector: () => null,
      getElementById: () => null,
    },
    localStorage: {getItem: () => null},
    getComputedStyle: () => ({getPropertyValue: () => ''}),
    fetch: () => new Promise(() => {}),
    requestAnimationFrame() {},
    setTimeout() {},
    setInterval() {},
    matchMedia: () => ({matches: false, addEventListener() {}}),
  });
  for (const name of ['kit.js', 'app.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'vps2vpn', 'static', name), 'utf8'),
                    context, {filename: name});
  }
  return context;
}

test('editing an expiry date preserves the local calendar day', () => {
  const previous = process.env.TZ;
  try {
    for (const zone of ['America/Los_Angeles', 'UTC', 'Asia/Singapore']) {
      process.env.TZ = zone;
      const ctx = frontend();
      for (const day of ['2026-01-15', '2026-07-15', '2026-11-01']) {
        ctx.day = day;
        assert.equal(vm.runInContext("dateStr(new Date(day + 'T23:59:59').getTime() / 1000)", ctx), day, zone);
      }
    }
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

test('detached sparklines leave the animation scheduler', () => {
  const ctx = frontend();
  vm.runInContext('spark({isConnected:false}, [1,2]); Ticker.frame(100)', ctx);
  assert.equal(vm.runInContext('Ticker.items.size', ctx), 0);
});

test('removing a detached chart disconnects its resize observer', () => {
  const ctx = frontend();
  vm.runInContext('globalThis.disconnected=0; Ticker.add({el:{isConnected:false}, observer:{disconnect(){disconnected++}}, tick(){throw Error("detached")}}); Ticker.frame(100)', ctx);
  assert.equal(ctx.disconnected, 1);
});

test('repeated theme mounts register one media-query listener', () => {
  const ctx = frontend();
  ctx.listeners = 0;
  ctx.matchMedia = () => ({addEventListener() {ctx.listeners++;}});
  vm.runInContext('Theme.mount(); Theme.mount(); Theme.mount()', ctx);
  assert.equal(ctx.listeners, 1);
});

test('expired-session refresh survives removal of the panel DOM', async () => {
  const ctx = frontend();
  ctx.visible = true;
  ctx.document.getElementById = () => ctx.visible ? {classList: {add() {}, remove() {}}} : null;
  await vm.runInContext('load=async()=>{globalThis.visible=false;throw Error("login")}; refresh()', ctx);
  assert.equal(vm.runInContext('S.refreshing', ctx), false);
});

test('slow state loads do not overlap periodic refreshes', async () => {
  const ctx = frontend();
  ctx.document.getElementById = () => ({classList: {add() {}, remove() {}}});
  vm.runInContext('globalThis.loads=0; load=()=>{loads++;return new Promise(resolve=>globalThis.finishLoad=resolve)}; loadDays=async()=>{}; updateHome=()=>{}; S.data={};', ctx);
  const first = vm.runInContext('refresh()', ctx);
  await vm.runInContext('refresh()', ctx);
  assert.equal(ctx.loads, 1);
  ctx.finishLoad();
  await first;
  assert.equal(vm.runInContext('S.refreshing', ctx), false);
});
