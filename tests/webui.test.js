// Run with: node --test tests/webui.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

class Element {
  constructor(tag = '') { this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.dataset = {}; this.style = {}; this.className = ''; this.value = ''; this.textContent = ''; this.classList = { toggle() {} }; }
  append(...nodes) { this.children.push(...nodes.flatMap(node => node.tag === 'fragment' ? node.children : [node])); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  getAttribute(name) { return this.attributes[name] ?? null; }
  focus() { this.focused = true; }
  click() { this.clicked = true; this.listeners.click?.(); }
  removeAttribute(name) { delete this.attributes[name]; }
  contains(node) { return this === node || this.children.some(child => child.contains(node)); }
  getBoundingClientRect() { return this.rect || { left: 20, top: 100, bottom: 148, width: 100 }; }
  get scrollHeight() { return this.children.length * 48 + 16; }
  scrollIntoView() {}
  dispatchEvent(event) { this.listeners[event.type]?.(event); }
}

function setup(bridge = true, dynamicColor = '', fixtureCertificates, fixtureApps) {
  const elements = new Map();
  const created = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, new Element(['save', 'apply', 'refresh', 'add-certificate', 'profile-filter'].includes(id) || id.startsWith('tab-') ? 'button' : ['search', 'certificate'].includes(id) ? 'input' : 'div'));
    return elements.get(id);
  };
  const calls = [];
  const timers = new Map();
  let timerId = 0;
  const hostile = '<img src=x onerror=alert(1)>';
  const certName = "a';$(touch /tmp/should-not-exist).0";
  const status = {
    ready: true, reason: '', assignments: { 'com.first.app': { '11111111.0': 'system' } }, globalCertificates: {},
    certificates: [{ name: '11111111.0', subject: 'Первый CA', fingerprint: 'AA:BB' }, { name: certName, subject: hostile, fingerprint: hostile }, { name: '33333333.0', subject: 'Третий CA', fingerprint: 'CC:DD' }], log: hostile,
  };
  if (fixtureCertificates) status.certificates = fixtureCertificates;
  const apps = fixtureApps || [
    { package: 'com.second.app', label: 'Альфа ' + hostile, uid: 10002, userId: 0, userName: 'Personal', profile: 'personal', icon: 'https://untrusted.example/icon.png' },
    { package: 'com.first.app', label: 'Яндекс', uid: 10001, userId: 0, userName: 'Personal', profile: 'personal', icon: 'app-icons/10001-com.first.app.png' },
  ];
  const argument = (command, name) => command.split(" '" + name + "' ")[1].slice(1, -1).replace(/'\\''/g, "'");
  const frames = [];
  const windowEvents = {}, documentEvents = {};
  const window = { innerWidth: 360, innerHeight: 720, addEventListener: (name, listener) => { windowEvents[name] = listener; }, requestAnimationFrame: callback => { frames.push(callback); setImmediate(() => { if (frames.includes(callback)) { frames.splice(frames.indexOf(callback), 1); callback(); } }); }, confirm: () => true, scrollTo() {}, getComputedStyle: () => ({ getPropertyValue: () => dynamicColor }) };
  if (bridge) window.ksu = { exec(command, options, callback) {
    calls.push({ command, options, callback });
    if (command.includes(" 'save-policy' ")) {
      status.assignments = {};
      status.globalCertificates = {};
      for (const line of argument(command, 'save-policy').split('\n').filter(Boolean)) {
        const [pkg, cert, mode = 'system'] = line.split(' ');
        if (pkg === '@global') status.globalCertificates[cert] = mode;
        else (status.assignments[pkg] ||= {})[cert] = mode;
      }
    }
    if (command.includes(" 'import-cert' ")) status.certificates.push({ name: '44444444.0', subject: 'Imported CA', fingerprint: 'EE:FF' });
    if (command.includes(" 'remove-cert' ")) {
      const name = argument(command, 'remove-cert');
      status.certificates = status.certificates.filter(cert => cert.name !== name);
      delete status.globalCertificates[name];
      for (const pkg of Object.keys(status.assignments)) {
        delete status.assignments[pkg][name];
        if (!Object.keys(status.assignments[pkg]).length) delete status.assignments[pkg];
      }
    }
    const stdout = command.endsWith("'status'") ? JSON.stringify(status) : command.endsWith("'apps'") ? JSON.stringify(apps) : '';
    window[callback](0, stdout, '');
  } };
  const document = {
    addEventListener: (name, listener) => { documentEvents[name] = listener; },
    getElementById: element,
    createElement: tag => { const node = new Element(tag); created.push(node); return node; },
    createDocumentFragment: () => new Element('fragment'),
    querySelector: () => element('file-label'),
    querySelectorAll: () => [...elements.values(), ...created].filter(el => ['button', 'input', 'select'].includes(el.tag) && el.attributes.role !== 'tab'),
  };
  for (const name of ['apps', 'certificates', 'status']) element('tab-' + name).attributes.role = 'tab';
  element('choice-menu').hidden = true;
  element('profile-filter').id = 'profile-filter';
  vm.runInNewContext(fs.readFileSync('webroot/app.js', 'utf8'), {
    window, document, Event, Uint8Array, TextDecoder, btoa: text => Buffer.from(text, 'binary').toString('base64'),
    setTimeout: fn => { timers.set(++timerId, fn); return timerId; }, clearTimeout: id => timers.delete(id),
  });
  return { element, calls, window, timers, hostile, certName, status, apps, frames, documentEvents, windowEvents };
}

const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve)); };
const packageOf = row => row.children[0].children[1].children[1].textContent;
const rowFor = (ui, key) => ui.element('apps').children.find(row => row.dataset.appKey === key);
const choice = (row, index) => row.children[1].children[index].children[0];
const setMode = (ui, pkg, index, mode) => {
  const select = choice(rowFor(ui, pkg), index);
  select.click();
  const option = ui.element('choice-menu').children.find(option => option.value === mode);
  assert.ok(option);
  option.click();
};
const setGlobalMode = (ui, index, mode) => {
  ui.element('global-certificates').children[index].children[0].click();
  const option = ui.element('choice-menu').children.find(option => option.value === mode);
  assert.ok(option);
  option.click();
};

test('loads assignments, sorts enabled apps first, saves per-app certificates and cleans callbacks', async () => {
  const ui = setup();
  await settle();
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.calls[0].options, '{}');
  assert.match(ui.calls[0].command, /^\/data\/adb\/ksu\/bin\/busybox sh \/data\/adb\/modules\/trustusercerts\/manage.sh 'status'$/);
  const rows = ui.element('apps').children;
  assert.equal(rows.length, 2);
  assert.equal(packageOf(rows[0]), 'com.first.app');
  assert.equal(choice(rows[0], 0).value, 'system');
  assert.equal(choice(rows[0], 1).value, 'inherit');
  setMode(ui, 'com.second.app', 0, 'system');
  assert.equal(packageOf(ui.element('apps').children[0]), 'com.second.app', 'Draft-enabled apps sort by real name immediately');
  setMode(ui, 'com.first.app', 0, 'inherit');
  assert.equal(choice(rowFor(ui, 'com.second.app'), 0).value, 'system');
  assert.equal(rowFor(ui, 'com.second.app').open, true);
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' 'com.second.app 11111111.0'")));
  assert.equal(ui.timers.size, 0);
  assert.equal(Object.keys(ui.window).filter(key => key.startsWith('tucCallback')).length, 0);
});

test('hostile certificate metadata stays text and delete argument is shell quoted', async () => {
  const ui = setup();
  await settle();
  const row = ui.element('certificates').children[1];
  assert.equal(row.children[0].textContent, 'Unnamed CA');
  assert.equal(row.children[1].children[1].textContent, ui.hostile);
  assert.equal(row.children[1].children[2].textContent, 'SHA-256: ' + ui.hostile);
  assert.equal(row.children[0].children.length, 0);
  row.children[2].listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'remove-cert' 'a'\\'';$(touch /tmp/should-not-exist).0'")));
});

test('without KSU the interface stays disabled and never invokes shell', () => {
  const ui = setup(false);
  assert.equal(ui.element('save').disabled, true);
  assert.equal(ui.calls.length, 0);
  assert.match(ui.element('status').textContent, /KernelSU/);
});

test('bridge timeout reports uncertain completion and cleans callback', async () => {
  const ui = setup();
  await settle();
  ui.window.ksu.exec = (command, options, callback) => ui.calls.push({ command, callback });
  ui.element('apply').listeners.click();
  await settle();
  assert.equal(ui.timers.size, 1);
  [...ui.timers.values()][0]();
  await settle();
  assert.match(ui.element('message').textContent, /operation may still be running/);
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.window[ui.calls.at(-1).callback], undefined);
});

test('imports bytes as base64 and rejects oversize files before shell execution', async () => {
  const ui = setup();
  await settle();
  const picker = ui.element('certificate');
  picker.files = [{ size: 3, arrayBuffer: async () => Uint8Array.from([0, 128, 255]).buffer }];
  picker.listeners.change();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'import-cert' 'AID/'")));
  const before = ui.calls.length;
  picker.files = [{ size: 65537 }];
  picker.listeners.change();
  await settle();
  assert.equal(ui.calls.length, before);
  assert.match(ui.element('message').textContent, /64 KiB/);
});

test('bottom tabs switch panels and remain usable without a root bridge', () => {
  const ui = setup(false);
  assert.equal(ui.element('panel-status').hidden, false);
  assert.equal(ui.element('panel-apps').hidden, true);
  assert.equal(ui.element('panel-certificates').hidden, true);
  ui.element('tab-certificates').listeners.click();
  assert.equal(ui.element('panel-apps').hidden, true);
  assert.equal(ui.element('panel-certificates').hidden, false);
  assert.equal(ui.element('tab-certificates').attributes['aria-selected'], 'true');
  assert.equal(ui.element('tab-apps').tabIndex, -1);
  let prevented = false;
  ui.element('tab-certificates').listeners.keydown({ key: 'ArrowRight', preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(ui.element('panel-apps').hidden, false);
  assert.equal(ui.element('tab-apps').focused, true);
  assert.notEqual(ui.element('tab-apps').disabled, true);
});

test('uses the official local KernelSU palette with CSS fallbacks for older managers', () => {
  const html = fs.readFileSync('webroot/index.html', 'utf8');
  const css = fs.readFileSync('webroot/style.css', 'utf8');
  assert.match(html, /href="\/internal\/colors\.css"/);
  assert.match(css, /--accent: var\(--primary, var\(--fallback-primary\)\)/);
  assert.match(css, /prefers-color-scheme: dark/);
  assert.match(css, /\[hidden\]\s*\{\s*display: none !important/);
});

test('real labels and safe icons render with fallbacks; search matches names and packages', async () => {
  const ui = setup();
  await settle();
  const first = rowFor(ui, 'com.first.app').children[0];
  assert.equal(first.children[1].children[0].textContent, 'Яндекс');
  const icon = first.children[0];
  assert.equal(icon.children[1].tag, 'img');
  assert.equal(icon.children[1].src, 'app-icons/10001-com.first.app.png');
  icon.children[1].listeners.load();
  assert.equal(icon.children[0].hidden, true);
  icon.children[1].listeners.error();
  assert.equal(icon.children[1].hidden, true);
  assert.equal(icon.children[0].hidden, false);
  assert.equal(icon.children[0].textContent, 'Я');
  const second = rowFor(ui, 'com.second.app').children[0];
  assert.equal(second.children[0].children.length, 1, 'Remote icons are rejected');
  assert.equal(second.children[1].children[0].textContent, 'Альфа ' + ui.hostile);
  assert.equal(second.children[1].children[0].children.length, 0, 'App label never becomes markup');
  ui.element('search').value = 'яндекс';
  ui.element('search').listeners.input();
  assert.deepEqual(ui.element('apps').children.map(packageOf), ['com.first.app']);
  ui.element('search').value = 'com.second';
  ui.element('search').listeners.input();
  assert.deepEqual(ui.element('apps').children.map(packageOf), ['com.second.app']);
});

test('whole policy saves global and per-app sets; import assigns nothing; deletion removes both', async () => {
  const ui = setup();
  await settle();
  const globalChoice = ui.element('global-certificates').children[2].children[0];
  globalChoice.value = 'system';
  globalChoice.listeners.change();
  assert.equal(ui.element('global-count').textContent, '1');
  assert.match(rowFor(ui, 'com.second.app').children[0].children[1].children[2].textContent, /1 System/);
  assert.equal(packageOf(ui.element('apps').children[0]), 'com.first.app', 'Individual assignments still rank above global-only apps');
  setMode(ui, 'com.first.app', 2, 'system');
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' '@global 33333333.0\ncom.first.app 11111111.0\ncom.first.app 33333333.0'")));
  const picker = ui.element('certificate');
  picker.files = [{ size: 3, arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer }];
  picker.listeners.change();
  await settle();
  assert.deepEqual(ui.status.globalCertificates, { '33333333.0': 'system' });
  assert.equal(ui.element('global-certificates').children[3].children[0].value, 'off');
  assert.equal(choice(rowFor(ui, 'com.first.app'), 3).value, 'inherit');
  setMode(ui, 'com.second.app', 0, 'system');
  ui.element('certificates').children[2].children[2].listeners.click();
  await settle();
  assert.equal(ui.element('global-count').textContent, '0');
  assert.deepEqual(ui.status.assignments['com.first.app'], { '11111111.0': 'system' });
  assert.equal(choice(rowFor(ui, 'com.second.app'), 0).value, 'system', 'Unrelated unsaved assignment survives certificate deletion');
  assert.equal(ui.element('global-certificates').children.length, 3);
});

test('action buttons show immediate feedback before the native bridge runs and restore after errors', async () => {
  const ui = setup();
  assert.equal(ui.element('operation').hidden, false);
  assert.match(ui.element('operation-text').textContent, /Loading/);
  await settle();
  assert.equal(ui.element('operation').hidden, true);
  const pending = [];
  ui.window.ksu.exec = (command, options, callback) => pending.push({ command, callback });
  ui.element('certificate').files = [{ size: 1, arrayBuffer: async () => Uint8Array.from([0]).buffer }];
  const remove = ui.element('certificates').children[0].children[2];
  const actions = [
    [ui.element('save'), () => ui.element('save').listeners.click(), /Saving/],
    [ui.element('refresh'), () => ui.element('refresh').listeners.click(), /Refreshing/],
    [ui.element('apply'), () => ui.element('apply').listeners.click(), /Applying/],
    [remove, () => remove.listeners.click(), /Deleting/],
    [ui.element('add-certificate'), () => ui.element('certificate').listeners.change(), /Importing/],
  ];
  for (const [button, action, label] of actions) {
    const original = button.textContent;
    action();
    assert.equal(ui.element('operation').hidden, true, 'Button actions do not show the top banner');
    assert.match(button.textContent, label);
    assert.equal(button.attributes['aria-busy'], 'true');
    assert.equal(button.disabled, true);
    assert.equal(pending.length, 0, 'The bridge waits for the loading state to paint');
    assert.ok(ui.frames.length);
    ui.element('tab-status').listeners.click();
    assert.equal(ui.element('panel-status').hidden, false);
    await settle();
    assert.equal(ui.element('panel-apps').attributes['aria-busy'], 'true');
    const call = pending.pop();
    assert.ok(call);
    ui.window[call.callback](1, '', 'Test backend error');
    await settle();
    assert.equal(button.textContent, original);
    assert.equal(button.attributes['aria-busy'], undefined);
    assert.equal(ui.element('panel-apps').attributes['aria-busy'], 'false');
    assert.equal(ui.element('message').textContent, 'Test backend error');
    assert.equal(ui.element('save').disabled, false);
    assert.equal(ui.timers.size, 0);
  }
});

test('custom import button opens the hidden picker and UI strings are English', async () => {
  const ui = setup();
  await settle();
  ui.element('add-certificate').listeners.click();
  assert.equal(ui.element('certificate').clicked, true);
  const html = fs.readFileSync('webroot/index.html', 'utf8');
  const js = fs.readFileSync('webroot/app.js', 'utf8');
  const css = fs.readFileSync('webroot/style.css', 'utf8');
  assert.match(html, /lang="en"/);
  assert.match(html, /id="certificate"[^>]*type="file"[^>]*hidden/);
  assert.doesNotMatch(html + js + fs.readFileSync('manage.sh', 'utf8'), /[А-Яа-яЁё]/);
  assert.match(css, /\.certificate-choice > span\s*\{[^}]*min-width: 0;[^}]*overflow-wrap: anywhere;/);
  assert.match(css, /button\[aria-busy=true\]::before/);
  assert.match(css, /prefers-reduced-motion: reduce/);
});


test('certificate titles use CN or organization, decode escaped values and keep full details collapsed', async () => {
  const fingerprint = Array(32).fill('AB').join(':');
  const subjects = [
    ['CN=Russian Trusted Root CA,O=Ministry,C=RU', 'Russian Trusted Root CA'],
    [String.raw`OU=https://reqable.com/+CN=Reqable CA (Mar 21\, 2024\, 8AA472BF),O=Reqable\, LLC,C=CN`, 'Reqable CA (Mar 21, 2024, 8AA472BF)'],
    [String.raw`CN=Test \D0\A1\D0\90,O=Issuer`, 'Test СА'],
    [String.raw`CN=Path\\41,O=Issuer`, String.raw`Path\41`],
    ['O=Organization,C=US', 'Organization'],
    ['C=US', 'Unnamed CA'],
    ['CN=<img src=x onerror=alert(1)>,O=Issuer', '<img src=x onerror=alert(1)>'],
  ];
  const ui = setup(true, '', subjects.map(([subject], i) => ({name: `${i}.0`, subject, fingerprint})));
  await settle();
  subjects.forEach(([subject, title], index) => {
    const row = ui.element('certificates').children[index];
    assert.equal(row.children[0].textContent, title);
    assert.equal(row.children[0].children.length, 0);
    assert.equal(row.children[1].tag, 'details');
    assert.notEqual(row.children[1].open, true);
    assert.equal(row.children[1].children[1].textContent, subject);
    assert.equal(row.children[1].children[2].textContent, 'SHA-256: ' + fingerprint);
    const choiceText = ui.element('global-certificates').children[index].children[1];
    assert.equal(choiceText.children[0].textContent, title);
    assert.equal(choiceText.children[1].textContent, 'AB:AB:AB:AB…AB:AB:AB:AB');
  });
});

test('minimal layout has Overview first, no persistent header, collapsed diagnostics and one floating Save', async () => {
  const html = fs.readFileSync('webroot/index.html', 'utf8');
  assert.doesNotMatch(html, /<header|id="page-title"|id="summary-status"|id="save-global"/);
  assert.match(html, /<details id="diagnostics" class="card">/);
  assert.doesNotMatch(html, /<details[^>]*\bopen\b/);
  assert.equal((html.match(/id="save"/g) || []).length, 1);
  assert.match(html, /id="save" class="save-fab"[^>]*hidden/);
  const tabIds = [...html.matchAll(/id="tab-([a-z]+)"/g)].map(match => match[1]);
  assert.deepEqual(tabIds, ['status', 'certificates', 'apps']);
  const ui = setup();
  await settle();
  assert.equal(ui.element('panel-status').hidden, false);
  assert.equal(ui.element('overview-apps').textContent, '1');
  assert.equal(ui.element('overview-certs').textContent, '3');
  assert.equal(ui.element('overview-global').textContent, '0');
  assert.equal(ui.element('status').textContent, 'Ready');
  assert.equal(ui.element('log').textContent, ui.hostile);
});

test('Save FAB appears only for a changed policy outside Overview and disappears after revert or deletion', async () => {
  const ui = setup();
  await settle();
  assert.equal(ui.element('save').hidden, true);
  ui.element('tab-apps').listeners.click();
  assert.equal(ui.element('save').hidden, true);
  setMode(ui, 'com.second.app', 0, 'system');
  assert.equal(ui.element('save').hidden, false);
  ui.element('tab-status').listeners.click();
  assert.equal(ui.element('save').hidden, true);
  ui.element('tab-certificates').listeners.click();
  assert.equal(ui.element('save').hidden, false);
  setMode(ui, 'com.second.app', 0, 'inherit');
  assert.equal(ui.element('save').hidden, true, 'Reverting individual choices clears dirty state');
  let global = ui.element('global-certificates').children[2].children[0];
  global.value = 'system';
  global.listeners.change();
  assert.equal(ui.element('save').hidden, false);
  global.value = 'off';
  global.listeners.change();
  assert.equal(ui.element('save').hidden, true, 'Reverting global choices clears dirty state');
  setMode(ui, 'com.first.app', 2, 'system');
  global.value = 'system';
  global.listeners.change();
  assert.equal(ui.element('save').hidden, false);
  ui.element('certificates').children[2].children[2].listeners.click();
  await settle();
  assert.equal(ui.element('save').hidden, true, 'Deleting the only edited CA clears both unsaved additions');
  assert.equal(ui.element('global-count').textContent, '0');
  assert.equal(choice(rowFor(ui, 'com.first.app'), 0).value, 'system');
});

test('same package in personal and work profiles has independent assignments, expansion, filtering and save keys', async () => {
  const ui = setup(true, '', undefined, [
    { package: 'com.first.app', label: 'Browser', userId: 0, userName: 'Personal', profile: 'personal' },
    { package: 'com.first.app', label: 'Browser', userId: 10, userName: 'Office', profile: 'work' },
  ]);
  await settle();
  assert.equal(ui.element('profile-filter-wrap').hidden, false);
  const personal = rowFor(ui, 'com.first.app');
  const work = rowFor(ui, '10:com.first.app');
  assert.equal(work.dataset.appKey, '10:com.first.app');
  assert.equal(choice(personal, 0).value, 'system');
  assert.equal(choice(work, 0).value, 'inherit');
  assert.equal(work.children[0].children[1].children[3].textContent, 'Work · Office');
  setMode(ui, '10:com.first.app', 2, 'system');
  assert.equal(choice(rowFor(ui, 'com.first.app'), 2).value, 'inherit');
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 2).value, 'system');
  assert.equal(rowFor(ui, '10:com.first.app').open, true);
  assert.notEqual(rowFor(ui, 'com.first.app').open, true);
  ui.element('profile-filter').value = '10';
  ui.element('profile-filter').listeners.change();
  assert.equal(ui.element('apps').children.length, 1);
  assert.equal(ui.element('apps').children[0].dataset.appKey, '10:com.first.app');
  ui.element('profile-filter').value = 'all';
  ui.element('search').value = 'office';
  ui.element('search').listeners.input();
  assert.equal(ui.element('apps').children.length, 1);
  assert.equal(ui.element('apps').children[0].dataset.appKey, '10:com.first.app');
  ui.element('search').value = '';
  ui.element('search').listeners.input();
  ui.element('tab-apps').listeners.click();
  ui.element('save').listeners.click();
  assert.equal(ui.element('save').attributes['aria-busy'], 'true');
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' '10:com.first.app 33333333.0\ncom.first.app 11111111.0'")));
  assert.equal(ui.element('save').hidden, true);
  assert.equal(ui.status.assignments['10:com.first.app']['33333333.0'], 'system');
});

test('profile filter stays hidden when installed apps share one profile', async () => {
  const ui = setup();
  await settle();
  assert.equal(ui.element('profile-filter-wrap').hidden, true);
});


test('icon paths reject traversal, remote URLs and icons belonging to another app', async () => {
  for (const icon of ['app-icons/../../private.png', 'https://example.com/icon.png', 'data:image/svg+xml,<svg/>', 'app-icons/10002-com.first.app.png', 'app-icons/10001-com.other.app.png']) {
    const ui = setup(true, '', undefined, [{package: 'com.first.app', uid: 10001, userId: 0, label: 'Browser', icon}]);
    await settle();
    assert.equal(rowFor(ui, 'com.first.app').children[0].children[0].children.length, 1, icon);
  }
});

test('typed CA choices retain explicit Off and use Inherit to remove a local override', async () => {
  const ui = setup();
  await settle();
  ui.element('tab-apps').listeners.click();
  const first = choice(rowFor(ui, 'com.first.app'), 0);
  assert.equal(first.tag, 'button');
  first.click();
  assert.deepEqual(ui.element('choice-menu').children.map(option => [option.value, option.textContent]), [
    ['inherit', 'Inherit'], ['off', 'Off'], ['system', 'System'], ['user', 'User'], ['both', 'Both'],
  ]);
  ui.element('choice-menu').listeners.keydown({ key: 'Escape', preventDefault() {} });
  setMode(ui, 'com.first.app', 0, 'user');
  assert.equal(ui.element('save').hidden, false);
  assert.match(rowFor(ui, 'com.first.app').children[0].children[1].children[2].textContent, /1 User/);
  assert.ok(!rowFor(ui, 'com.first.app').children[1].children.some(node => node.textContent === 'User trust requires app support.' || node.tag === 'legend'));
  setMode(ui, 'com.first.app', 0, 'both');
  assert.equal(choice(rowFor(ui, 'com.first.app'), 0).title, 'System trust can still trigger WebView limits.');
  setMode(ui, 'com.first.app', 0, 'system');
  assert.equal(ui.element('save').hidden, true);
  setMode(ui, 'com.first.app', 0, 'off');
  assert.equal(ui.element('save').hidden, false);
  ui.element('save').listeners.click();
  await settle();
  assert.deepEqual(ui.status.assignments, { 'com.first.app': { '11111111.0': 'off' } });
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' 'com.first.app 11111111.0 off'")));
  assert.match(choice(rowFor(ui, 'com.first.app'), 0).title, /original Android CAs remain trusted/);
  setMode(ui, 'com.first.app', 0, 'inherit');
  ui.element('save').listeners.click();
  await settle();
  assert.deepEqual(ui.status.assignments, {});
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' ''")));
  setMode(ui, 'com.first.app', 0, 'user');
  setMode(ui, 'com.first.app', 2, 'both');
  setMode(ui, 'com.second.app', 0, 'system');
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' 'com.first.app 11111111.0 user\ncom.first.app 33333333.0 both\ncom.second.app 11111111.0'")));
  assert.deepEqual(ui.status.assignments, {
    'com.first.app': { '11111111.0': 'user', '33333333.0': 'both' },
    'com.second.app': { '11111111.0': 'system' },
  });
  assert.equal(ui.element('save').hidden, true);
});

test('explicit profile assignments override global modes instead of combining with them', async () => {
  const ui = setup(true, '', undefined, [
    { package: 'com.first.app', label: 'Browser', userId: 0, userName: 'Personal', profile: 'personal' },
    { package: 'com.first.app', label: 'Browser', userId: 10, userName: 'Office', profile: 'work' },
  ]);
  await settle();
  ui.element('tab-apps').listeners.click();
  setMode(ui, '10:com.first.app', 0, 'user');
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' '10:com.first.app 11111111.0 user\ncom.first.app 11111111.0'")));
  assert.equal(choice(rowFor(ui, 'com.first.app'), 0).value, 'system');
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 0).value, 'user');
  ui.element('tab-certificates').listeners.click();
  const global = ui.element('global-certificates').children[0].children[0];
  global.value = 'system';
  global.listeners.change();
  assert.equal(ui.element('global-mode-note').hidden, true);
  assert.match(rowFor(ui, '10:com.first.app').children[0].children[1].children[2].textContent, /1 User/);
  assert.match(rowFor(ui, 'com.first.app').children[0].children[1].children[2].textContent, /1 System/);
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 0).title, '');
  global.value = 'user';
  global.listeners.change();
  assert.equal(ui.element('global-mode-note').hidden, false);
  assert.match(rowFor(ui, 'com.first.app').children[0].children[1].children[2].textContent, /1 System/);
  assert.match(rowFor(ui, '10:com.first.app').children[0].children[1].children[2].textContent, /1 User/);
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' '10:com.first.app 11111111.0 user\n@global 11111111.0 user\ncom.first.app 11111111.0'")));
  assert.deepEqual(ui.status.globalCertificates, { '11111111.0': 'user' });
  const savedGlobal = ui.element('global-certificates').children[0].children[0];
  savedGlobal.value = 'both';
  savedGlobal.listeners.change();
  assert.equal(ui.element('save').hidden, false);
  assert.equal(savedGlobal.title, 'System trust can still trigger WebView limits.');
  assert.match(rowFor(ui, '10:com.first.app').children[0].children[1].children[2].textContent, /1 User/);
  savedGlobal.value = 'user';
  savedGlobal.listeners.change();
  assert.equal(ui.element('save').hidden, true, 'Reverting a global mode clears dirty state');
});

test('themed menus replace all native selects and keyboard selection returns focus with an updated accessible value', async () => {
  const html = fs.readFileSync('webroot/index.html', 'utf8');
  const js = fs.readFileSync('webroot/app.js', 'utf8');
  assert.doesNotMatch(html, /<select\b|<option\b/i);
  assert.doesNotMatch(js, /createElement\(['"](?:select|option)['"]\)/);
  assert.equal((html.match(/role="listbox"/g) || []).length, 1);
  const ui = setup();
  await settle();
  const trigger = choice(rowFor(ui, 'com.first.app'), 0);
  const menu = ui.element('choice-menu');
  const key = value => menu.listeners.keydown({ key: value, preventDefault() {} });
  trigger.listeners.keydown({ key: 'ArrowDown', preventDefault() {} });
  assert.equal(trigger.attributes['aria-expanded'], 'true');
  assert.equal(trigger.attributes['aria-controls'], 'choice-menu');
  assert.match(trigger.attributes['aria-label'], /: System$/);
  assert.equal(menu.attributes['aria-labelledby'], trigger.id);
  assert.equal(menu.children[2].attributes['aria-selected'], 'true');
  assert.equal(menu.attributes['aria-activedescendant'], menu.children[2].id);
  key('ArrowDown');
  assert.equal(menu.attributes['aria-activedescendant'], menu.children[3].id);
  key('Home');
  assert.equal(menu.attributes['aria-activedescendant'], menu.children[0].id);
  key('ArrowUp');
  assert.equal(menu.attributes['aria-activedescendant'], menu.children[4].id);
  key('ArrowDown');
  assert.equal(menu.attributes['aria-activedescendant'], menu.children[0].id);
  key('End');
  key(' ');
  assert.equal(menu.hidden, true);
  assert.equal(trigger.attributes['aria-expanded'], 'false');
  const updated = choice(rowFor(ui, 'com.first.app'), 0);
  assert.equal(updated.value, 'both');
  assert.equal(updated.focused, true);
  assert.match(updated.attributes['aria-label'], /: Both$/);
  updated.click();
  key('Home');
  key('Escape');
  assert.equal(menu.hidden, true);
  assert.equal(updated.value, 'both', 'Escape discards only the menu highlight');
  updated.click();
  let prevented = false;
  menu.listeners.keydown({ key: 'Tab', preventDefault() { prevented = true; } });
  assert.equal(menu.hidden, true);
  assert.equal(prevented, false, 'Tab remains normal focus navigation');
  assert.equal(updated.focused, true);
});

test('menus clamp to the viewport, flip upward and close on outside, scrolling, section changes or busy actions', async () => {
  const ui = setup();
  await settle();
  const trigger = choice(rowFor(ui, 'com.first.app'), 0);
  const menu = ui.element('choice-menu');
  trigger.rect = { left: 330, top: 650, bottom: 698, width: 100 };
  trigger.click();
  assert.equal(menu.style.transformOrigin, 'bottom left');
  assert.ok(parseFloat(menu.style.left) + parseFloat(menu.style.width) <= ui.window.innerWidth - 8);
  assert.ok(parseFloat(menu.style.top) + parseFloat(menu.style.maxHeight) < trigger.rect.top);
  ui.documentEvents.pointerdown({ target: menu.children[0] });
  assert.equal(menu.hidden, false, 'Inside events do not dismiss the menu');
  ui.documentEvents.pointerdown({ target: ui.element('message') });
  assert.equal(menu.hidden, true);
  trigger.click();
  ui.documentEvents.scroll({ target: menu });
  assert.equal(menu.hidden, false, 'The list itself can scroll');
  ui.documentEvents.scroll({ target: ui.element('apps') });
  assert.equal(menu.hidden, true);
  trigger.click();
  ui.element('tab-certificates').listeners.click();
  assert.equal(menu.hidden, true);
  trigger.click();
  ui.windowEvents.resize();
  assert.equal(menu.hidden, true);
  trigger.disabled = true;
  trigger.click();
  assert.equal(menu.hidden, true);
  trigger.disabled = false;
  trigger.click();
  ui.element('refresh').listeners.click();
  assert.equal(menu.hidden, true, 'Async work dismisses the menu before yielding for paint');
  trigger.click();
  assert.equal(menu.hidden, true, 'Busy actions prevent opening a stale trigger');
  await settle();
  const css = fs.readFileSync('webroot/style.css', 'utf8');
  assert.match(css, /\.choice-menu[^}]*animation: menu-in/);
  assert.match(css, /prefers-reduced-motion: reduce\)\s*\{\s*\.choice-menu\s*\{\s*animation: none/);
  assert.match(css, /button\.choice-option[^}]*min-height: 48px/);
});

test('profile filtering uses the same WebUI popup and selected value rather than a native picker', async () => {
  const ui = setup(true, '', undefined, [
    { package: 'com.first.app', label: 'Browser', userId: 0, profile: 'personal' },
    { package: 'com.first.app', label: 'Browser', userId: 10, userName: 'Office', profile: 'work' },
  ]);
  await settle();
  const trigger = ui.element('profile-filter');
  trigger.click();
  const menu = ui.element('choice-menu');
  assert.equal(menu.hidden, false);
  assert.deepEqual(menu.children.map(option => option.textContent), ['All profiles', 'Personal', 'Work · Office']);
  menu.children[2].click();
  assert.equal(menu.hidden, true);
  assert.equal(trigger.value, '10');
  assert.equal(trigger.textContent, 'Work · Office');
  assert.equal(trigger.focused, true);
  assert.equal(ui.element('apps').children.length, 1);
  assert.equal(ui.element('apps').children[0].dataset.appKey, '10:com.first.app');
});

test('global System can be excluded or replaced per profile; Inherit restores the actual global mode', async () => {
  const ui = setup(true, '', undefined, [
    { package: 'com.first.app', label: 'Browser', userId: 0, profile: 'personal' },
    { package: 'com.first.app', label: 'Browser', userId: 10, userName: 'Office', profile: 'work' },
  ]);
  await settle();
  ui.element('tab-apps').listeners.click();
  setGlobalMode(ui, 0, 'system');
  const badge = key => rowFor(ui, key).children[0].children[1].children[2];
  const caption = key => rowFor(ui, key).children[1].children[0].children[1].children[2].textContent;
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 0).value, 'inherit');
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 0).disabled, false);
  assert.equal(caption('10:com.first.app'), 'Inherited: System');
  assert.equal(badge('10:com.first.app').textContent, '1 System');
  setMode(ui, '10:com.first.app', 0, 'off');
  assert.equal(badge('10:com.first.app').textContent, 'Off');
  assert.equal(badge('10:com.first.app').className, 'app-disabled');
  assert.equal(caption('10:com.first.app'), 'Effective: Off');
  assert.equal(ui.element('selected-count').textContent, '2', 'Off exceptions remain individually configured');
  assert.equal(badge('com.first.app').textContent, '1 System', 'The other profile remains independent');
  ui.element('save').listeners.click();
  await settle();
  assert.ok(ui.calls.some(call => call.command.endsWith("'save-policy' '10:com.first.app 11111111.0 off\n@global 11111111.0\ncom.first.app 11111111.0'")));
  assert.equal(ui.status.assignments['10:com.first.app']['11111111.0'], 'off');
  setMode(ui, '10:com.first.app', 0, 'user');
  assert.equal(badge('10:com.first.app').textContent, '1 User');
  assert.equal(caption('10:com.first.app'), 'Effective: User');
  setMode(ui, '10:com.first.app', 0, 'both');
  assert.equal(badge('10:com.first.app').textContent, '1 Both');
  setMode(ui, '10:com.first.app', 0, 'inherit');
  assert.equal(caption('10:com.first.app'), 'Inherited: System');
  assert.equal(choice(rowFor(ui, '10:com.first.app'), 0).title, 'Use global setting');
  assert.equal(ui.element('save').hidden, false);
  setMode(ui, '10:com.first.app', 0, 'off');
  assert.equal(ui.element('save').hidden, true, 'Restoring the saved exclusion clears dirty state');
  setMode(ui, '10:com.first.app', 0, 'inherit');
  ui.element('save').listeners.click();
  await settle();
  assert.equal(ui.status.assignments['10:com.first.app'], undefined);
  setGlobalMode(ui, 0, 'user');
  assert.equal(caption('10:com.first.app'), 'Inherited: User');
  assert.equal(badge('10:com.first.app').textContent, '1 User');
  assert.equal(badge('com.first.app').textContent, '1 System');
  setGlobalMode(ui, 0, 'both');
  assert.equal(caption('10:com.first.app'), 'Inherited: Both');
  assert.equal(badge('10:com.first.app').textContent, '1 Both');
  const global = ui.element('global-certificates').children[0].children[0];
  global.click();
  assert.deepEqual(ui.element('choice-menu').children.map(option => option.value), ['off', 'system', 'user', 'both']);
  ui.element('choice-menu').children[0].click();
  assert.equal(badge('10:com.first.app').textContent, 'Off');
  assert.equal(ui.element('global-count').textContent, '0');
});

test('the save warning stays visible before edits, while dirty and after reverting', async () => {
  const html = fs.readFileSync('webroot/index.html', 'utf8');
  assert.match(html, /<p id="selection-note"[^>]*>Saving stops configured apps\.<\/p>/);
  const ui = setup();
  await settle();
  const warning = ui.element('selection-note').textContent;
  assert.equal(warning, 'Saving stops configured apps.');
  ui.element('tab-apps').listeners.click();
  setMode(ui, 'com.first.app', 0, 'user');
  assert.equal(ui.element('save').hidden, false);
  assert.equal(ui.element('selection-note').textContent, warning);
  setMode(ui, 'com.first.app', 0, 'system');
  assert.equal(ui.element('save').hidden, true);
  assert.equal(ui.element('selection-note').textContent, warning);
});
