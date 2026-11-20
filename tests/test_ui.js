'use strict';
// Resource-lifetime and quota regressions; no DOM rendering or external requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

let mediaListeners = 0;
const observers = new Set();
function element() {
  return {
    isConnected: true, offsetParent: {},
    append() {}, addEventListener() {}, setAttribute() {}, removeAttribute() {},
    getClientRects() { return [{}]; },
  };
}
const button = element();
button.dataset = {themeBtn: 'auto'};
const document = {
  hidden: false, documentElement: element(), addEventListener() {},
  createElement: element, querySelectorAll() { return [button]; },
};
const context = {
  document, window: {}, performance: {now() { return 0; }},
  requestAnimationFrame() { return 0; },
  getComputedStyle() { return {getPropertyValue() { return '#000000'; }}; },
  matchMedia() { return {addEventListener() { mediaListeners++; }}; },
  ResizeObserver: class {
    constructor() { observers.add(this); }
    observe() {}
    disconnect() { observers.delete(this); }
  },
};
vm.runInNewContext(fs.readFileSync('vps2vpn/static/kit.js', 'utf8') +
  '\nglobalThis.kit = {Ticker, Theme, Ring, quotaUsage};', context);
const {Ticker, Theme, Ring, quotaUsage} = context.kit;

for (let i = 0; i < 25; i++) {
  const el = element();
  new Ring(el);
  assert.equal(observers.size, 1);
  el.isConnected = false;
  Ticker.frame(1000);
  assert.equal(observers.size, 0);
  assert.equal(Ticker.items.size, 0);
}
for (let i = 0; i < 25; i++) Theme.mount();
assert.equal(mediaListeners, 1);

const unlimited = quotaUsage({quota_gb: 0, quota_eff: 0, used_down: 123});
assert.equal(unlimited.limited, false);
assert.equal(unlimited.ratio, 0);
const exhausted = quotaUsage({quota_gb: 10, quota_eff: 0});
assert.equal(exhausted.limited, true);
assert.equal(exhausted.limit, 0);
assert.equal(exhausted.ratio, 1);
const half = quotaUsage({quota_gb: 10, quota_eff: 2, used_down: 1073741824});
assert.equal(half.limit, 2147483648);
assert.equal(half.ratio, 0.5);

console.log('UI regression checks passed: detached observers, theme listener, finite zero quota.');
