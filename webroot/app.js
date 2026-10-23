(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const bridge = window.ksu && typeof window.ksu.exec === 'function';
  const assignments = new Map();
  const hooks = new Map();
  const globalCertificates = new Map();
  const expanded = new Set();
  let apps = [], certificates = [], busy = false, dirty = false, callbackId = 0, activeTab = 'status', savedPolicy = '';
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  const tabs = ['status', 'certificates', 'apps'];
  const menu = $('choice-menu');
  let openChoice = null, choiceId = 0;

  function closeChoice(returnFocus = false) {
    if (!openChoice) return;
    const trigger = openChoice.trigger;
    openChoice = null;
    trigger.setAttribute('aria-expanded', 'false');
    menu.hidden = true;
    menu.removeAttribute('aria-activedescendant');
    if (returnFocus) trigger.focus();
  }

  function focusChoice(index) {
    const buttons = [...menu.children];
    openChoice.index = (index + buttons.length) % buttons.length;
    buttons.forEach((button, i) => { button.dataset.active = String(i === openChoice.index); });
    const active = buttons[openChoice.index];
    menu.setAttribute('aria-activedescendant', active.id);
    active.scrollIntoView({ block: 'nearest' });
  }

  function openChoices(trigger, options, index) {
    if (busy || !bridge || trigger.disabled) return;
    closeChoice();
    openChoice = { trigger, index: 0 };
    const fragment = document.createDocumentFragment();
    options.forEach(option => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'choice-option';
      item.id = `choice-option-${++choiceId}`;
      item.tabIndex = -1;
      item.value = option.value;
      item.textContent = option.label;
      item.title = option.title || '';
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', String(option.value === trigger.value));
      item.addEventListener('click', () => {
        closeChoice(true);
        trigger.value = option.value;
        trigger.dispatchEvent(new Event('change'));
      });
      fragment.append(item);
    });
    menu.replaceChildren(fragment);
    menu.setAttribute('aria-labelledby', trigger.id);
    trigger.setAttribute('aria-expanded', 'true');
    menu.hidden = false;
    const rect = trigger.getBoundingClientRect();
    const width = Math.min(Math.max(192, rect.width), window.innerWidth - 16);
    menu.style.width = width + 'px';
    menu.style.maxHeight = Math.max(0, window.innerHeight - 16) + 'px';
    const desiredHeight = Math.min(menu.scrollHeight, window.innerHeight - 16);
    const below = window.innerHeight - rect.bottom - 8;
    const above = rect.top - 8;
    const flip = below < desiredHeight && above > below;
    const height = Math.max(0, Math.min(desiredHeight, flip ? above : below));
    menu.style.maxHeight = height + 'px';
    menu.style.left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)) + 'px';
    menu.style.top = Math.max(8, Math.min(flip ? rect.top - height - 4 : rect.bottom + 4, window.innerHeight - height - 8)) + 'px';
    menu.style.transformOrigin = flip ? 'bottom left' : 'top left';
    menu.focus();
    focusChoice(index < 0 ? Math.max(0, options.findIndex(option => option.value === trigger.value)) : index);
  }

  function configureChoice(trigger, options, value, change) {
    const accessibleLabel = trigger.getAttribute('aria-label');
    const updateLabel = () => {
      trigger.textContent = options.find(option => option.value === trigger.value)?.label || '';
      if (accessibleLabel) trigger.setAttribute('aria-label', accessibleLabel + ': ' + trigger.textContent);
    };
    trigger.type = 'button';
    trigger.className += ' select-trigger';
    trigger.id ||= `choice-trigger-${++choiceId}`;
    trigger.value = value;
    updateLabel();
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-controls', 'choice-menu');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.addEventListener('click', () => {
      if (openChoice?.trigger === trigger) closeChoice(true); else openChoices(trigger, options, -1);
    });
    trigger.addEventListener('keydown', event => {
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      openChoices(trigger, options, event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1 : -1);
    });
    trigger.addEventListener('change', () => {
      updateLabel();
      change(trigger.value);
    });
    return trigger;
  }

  menu.addEventListener('keydown', event => {
    if (!openChoice) return;
    if (event.key === 'Escape' || event.key === 'Tab') {
      if (event.key === 'Escape') event.preventDefault();
      closeChoice(true);
    } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      focusChoice(event.key === 'Home' ? 0 : event.key === 'End' ? menu.children.length - 1 : openChoice.index + (event.key === 'ArrowDown' ? 1 : -1));
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      menu.children[openChoice.index].click();
    }
  });
  document.addEventListener('pointerdown', event => {
    if (openChoice && !menu.contains(event.target) && !openChoice.trigger.contains(event.target)) closeChoice();
  }, true);
  document.addEventListener('scroll', event => { if (openChoice && !menu.contains(event.target)) closeChoice(); }, { capture: true, passive: true });
  window.addEventListener('resize', () => closeChoice());
  const appKey = app => app.userId ? `${app.userId}:${app.package}` : app.package;
  const profileName = app => {
    if (!app.userId) return 'Personal';
    const type = app.profile === 'work' ? 'Work' : `User ${app.userId}`;
    const name = (app.userName || '').trim();
    return name && name.toLowerCase() !== type.toLowerCase() ? `${type} · ${name}` : type;
  };

  const rule = (key, name, mode) => `${key} ${name}${mode === 'system' ? '' : ' ' + mode}`;
  const offHint = 'Disable module CA injection only; original Android CAs remain trusted.';
  function policyRecords(applicationSets = assignments, globalSet = globalCertificates, hookSets = hooks) {
    const records = [...globalSet].map(([name, mode]) => rule('@global', name, mode));
    for (const [key, names] of applicationSets) for (const [name, mode] of names) records.push(rule(key, name, mode));
    for (const [key, flags] of hookSets) {
      const bits = (flags.disableCT ? 1 : 0) | (flags.trustUserCAs ? 2 : 0) | (flags.trustSystemCAs ? 4 : 0);
      const mode = ['', 'ct', 'user', 'both', 'system', 'ct-system', 'user-system', 'all'][bits];
      if (mode) records.push(`${key} @hooks ${mode}`);
    }
    return records.sort().join('\n');
  }

  function effectiveModes(key) {
    const modes = new Map(globalCertificates);
    for (const [name, mode] of assignments.get(key) || []) {
      if (mode === 'off') modes.delete(name); else modes.set(name, mode);
    }
    return modes;
  }

  function modeSelect(cert, mode, effective, change, individual = false) {
    const select = document.createElement('button');
    select.className = 'trust-mode';
    select.setAttribute('aria-label', `Trust mode for ${certificateName(cert)}`);
    const options = individual ? ['inherit', 'off', 'system', 'user', 'both'] : ['off', 'system', 'user', 'both'];
    const current = mode || (individual ? 'inherit' : 'off');
    configureChoice(select, options.map(value => ({
      value, label: value[0].toUpperCase() + value.slice(1),
      title: value === 'inherit' ? 'Use global setting' : value === 'off' ? offHint : value === 'both' ? 'System trust can still trigger WebView limits.' : '',
    })), current, change);
    select.title = current === 'inherit' ? 'Use global setting' : current === 'off' ? offHint : effective === 'both' ? 'System trust can still trigger WebView limits.' : '';
    select.disabled = busy || !bridge;
    return select;
  }

  function updateSave() {
    dirty = policyRecords() !== savedPolicy;
    $('save').hidden = !dirty || activeTab === 'status';
  }

  function certificateName(cert) {
    for (const attribute of ['CN', 'O']) {
      const match = (cert.subject || '').match(new RegExp('(?:^|[,+])' + attribute + '=((?:\\\\.|[^,+])*)'));
      if (!match || !match[1] || match[1].startsWith('#')) continue;
      return match[1].replace(/(?:\\[0-9a-f]{2})+|\\./gi, escaped => {
        if (!/^\\[0-9a-f]{2}/i.test(escaped)) return escaped.slice(1);
        return new TextDecoder().decode(Uint8Array.from(escaped.match(/[0-9a-f]{2}/gi), hex => parseInt(hex, 16)));
      });
    }
    return 'Unnamed CA';
  }

  function shortFingerprint(cert) {
    const value = cert.fingerprint || cert.name;
    return value.length > 31 ? value.slice(0, 11) + '…' + value.slice(-11) : value;
  }

  function selectTab(name, focus = false) {
    closeChoice();
    activeTab = name;
    tabs.forEach(tab => {
      const active = tab === name;
      $('tab-' + tab).setAttribute('aria-selected', String(active));
      $('tab-' + tab).tabIndex = active ? 0 : -1;
      $('panel-' + tab).hidden = !active;
    });
    if (focus) $('tab-' + name).focus();
    updateSave();
    window.scrollTo(0, 0);
  }
  tabs.forEach((name, index) => {
    $('tab-' + name).addEventListener('click', () => selectTab(name));
    $('tab-' + name).addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) { event.preventDefault(); selectTab(tabs[next], true); }
    });
  });
  selectTab('status');

  function exec(command, ...args) {
    return new Promise((resolve, reject) => {
      if (!bridge) return reject(new Error('Open the module WebUI in KernelSU.'));
      const name = `tucCallback${++callbackId}`;
      const cleanup = () => { clearTimeout(timer); delete window[name]; };
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('KernelSU did not respond within 60 seconds. The operation may still be running; reopen the WebUI to check.'));
      }, 60000);
      window[name] = (errno, stdout, stderr) => {
        cleanup();
        if (Number(errno) !== 0) reject(new Error(stderr || stdout || `Command failed: ${errno}`));
        else resolve(String(stdout || ''));
      };
      try {
        window.ksu.exec('/data/adb/ksu/bin/busybox sh /data/adb/modules/trustusercerts/manage.sh ' + [command, ...args].map(quote).join(' '), JSON.stringify({}), name);
      } catch (error) { cleanup(); reject(error); }
    });
  }

  function controls() {
    document.querySelectorAll('button:not([role="tab"]), input').forEach(el => { el.disabled = busy || !bridge; });
    tabs.forEach(tab => $('panel-' + tab).setAttribute('aria-busy', String(busy)));
  }

  async function run(action, label, button) {
    if (busy) return;
    closeChoice();
    busy = true;
    $('message').textContent = '';
    $('operation-text').textContent = label;
    $('operation').hidden = Boolean(button);
    const original = button?.textContent;
    if (button) {
      button.textContent = label;
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    }
    try {
      // Let WebView paint feedback before the native bridge can block its UI thread.
      await new Promise(resolve => window.requestAnimationFrame(() => window.requestAnimationFrame(resolve)));
      controls();
      await action();
    }
    catch (error) { $('message').textContent = error.message; }
    finally {
      if (button) { button.textContent = original; button.removeAttribute('aria-busy'); }
      busy = false;
      $('operation').hidden = true;
      controls();
    }
  }

  function renderApps(focusPackage, focusCertificate, focusHook) {
    closeChoice();
    const query = $('search').value.trim().toLowerCase();
    const fragment = document.createDocumentFragment();
    const all = new Map(apps.map(app => [appKey(app), app]));
    for (const key of new Set([...assignments.keys(), ...hooks.keys()])) if (!all.has(key)) {
      const separator = key.indexOf(':');
      const pkg = separator < 0 ? key : key.slice(separator + 1);
      all.set(key, { package: pkg, label: pkg, userId: separator < 0 ? 0 : Number(key.slice(0, separator)) });
    }
    const count = pkg => (assignments.get(pkg)?.size || 0) + Number(hooks.has(pkg));
    const profile = $('profile-filter').value || 'all';
    const visible = [...all.values()].filter(app => (profile === 'all' || String(app.userId || 0) === profile) &&
      `${app.label || app.package} ${app.package} ${profileName(app)}`.toLowerCase().includes(query))
      .sort((a, b) => Number(count(appKey(b)) > 0) - Number(count(appKey(a)) > 0) ||
        (a.label || a.package).localeCompare(b.label || b.package, 'en') || a.package.localeCompare(b.package) || (a.userId || 0) - (b.userId || 0));
    let focusTarget;
    for (const app of visible) {
      const pkg = appKey(app);
      const row = document.createElement('details');
      row.className = 'app';
      row.dataset.appKey = pkg;
      row.open = expanded.has(pkg);
      row.addEventListener('toggle', () => {
        if (row.open) expanded.add(pkg); else expanded.delete(pkg);
      });
      const summary = document.createElement('summary');
      summary.className = 'app-summary';
      const icon = document.createElement('span');
      icon.className = 'app-icon';
      const fallback = document.createElement('span');
      fallback.textContent = (app.label || pkg).slice(0, 1).toLocaleUpperCase('en');
      fallback.setAttribute('aria-hidden', 'true');
      icon.append(fallback);
      if (typeof app.icon === 'string' && app.icon === `app-icons/${app.uid}-${app.package}.png` &&
          /^app-icons\/[0-9]+-[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\.png$/.test(app.icon)) {
        const image = document.createElement('img');
        image.alt = '';
        image.loading = 'lazy';
        image.src = app.icon;
        image.addEventListener('load', () => { fallback.hidden = true; });
        image.addEventListener('error', () => { image.hidden = true; fallback.hidden = false; });
        icon.append(image);
      }
      const text = document.createElement('span');
      text.className = 'app-name';
      const name = document.createElement('strong');
      name.textContent = app.label || pkg;
      const identifier = document.createElement('small');
      identifier.textContent = app.package;
      const badge = document.createElement('small');
      const effective = effectiveModes(pkg);
      const flags = hooks.get(pkg);
      badge.className = effective.size || flags ? 'app-enabled' : 'app-disabled';
      badge.textContent = [...['system', 'user', 'both'].map(mode => {
        const total = [...effective.values()].filter(value => value === mode).length;
        return total ? `${total} ${mode[0].toUpperCase() + mode.slice(1)}` : '';
      }), flags?.disableCT ? 'CT off' : '', flags?.trustUserCAs ? 'User CAs' : '', flags?.trustSystemCAs ? 'System CAs' : ''].filter(Boolean).join(' · ') || 'Off';
      text.append(name, identifier, badge);
      const profileBadge = document.createElement('small');
      profileBadge.className = 'profile-badge';
      profileBadge.textContent = profileName(app);
      text.append(profileBadge);
      summary.append(icon, text);
      const choices = document.createElement('fieldset');
      choices.className = 'app-certificates';
      choices.setAttribute('aria-label', `Certificates for ${app.label || app.package}`);
      for (const cert of certificates) {
        const label = document.createElement('label');
        label.className = 'certificate-choice';
        const select = modeSelect(cert, assignments.get(pkg)?.get(cert.name), effective.get(cert.name), mode => {
          const names = assignments.get(pkg) || new Map();
          if (mode !== 'inherit') names.set(cert.name, mode); else names.delete(cert.name);
          if (names.size) assignments.set(pkg, names); else assignments.delete(pkg);
          expanded.add(pkg);
          renderApps(pkg, cert.name);
        }, true);
        const description = document.createElement('span');
        const subject = document.createElement('strong');
        subject.textContent = certificateName(cert);
        const fingerprint = document.createElement('small');
        fingerprint.textContent = shortFingerprint(cert);
        description.append(subject, fingerprint);
        if (globalCertificates.has(cert.name)) {
          const inherited = document.createElement('small');
          const mode = effective.get(cert.name) || 'off';
          inherited.textContent = (assignments.get(pkg)?.has(cert.name) ? 'Effective: ' : 'Inherited: ') + mode[0].toUpperCase() + mode.slice(1);
          description.append(inherited);
        }
        label.append(select, description);
        choices.append(label);
        if (pkg === focusPackage && cert.name === focusCertificate) focusTarget = select;
      }
      if (!certificates.length) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'First add a certificate in the Certificates tab.';
        const add = document.createElement('button');
        add.type = 'button';
        add.className = 'secondary';
        add.textContent = 'Add certificate';
        add.disabled = busy || !bridge;
        add.addEventListener('click', () => { selectTab('certificates', true); $('add-certificate').focus(); });
        choices.append(empty, add);
      }
      const hookChoices = document.createElement('fieldset');
      hookChoices.className = 'app-hooks';
      hookChoices.setAttribute('aria-label', `TLS options for ${app.label || app.package}, ${profileName(app)}`);
      for (const [feature, title, description] of [
        ['disableCT', 'Disable CT', 'Disable Android Certificate Transparency checks for this app. Its own TLS stack may not be covered.'],
        ['trustSystemCAs', 'Trust system CAs', 'Trust existing or injected Android system CA anchors. Certificate pinning, expiry and hostname checks remain.'],
        ['trustUserCAs', 'Trust user CAs', 'Trust existing or injected Android user CA anchors. Certificate pinning, expiry and hostname checks remain.'],
      ]) {
        const label = document.createElement('label');
        label.className = 'hook-choice';
        const text = document.createElement('span');
        text.textContent = title;
        const toggle = document.createElement('input');
        toggle.type = 'checkbox';
        toggle.className = 'hook-switch';
        toggle.dataset.hook = feature;
        toggle.checked = flags?.[feature] === true;
        toggle.disabled = busy || !bridge;
        toggle.setAttribute('role', 'switch');
        toggle.setAttribute('aria-checked', String(toggle.checked));
        toggle.setAttribute('aria-label', `${title} for ${app.label || app.package}, ${profileName(app)}`);
        toggle.setAttribute('aria-description', description);
        toggle.title = description;
        toggle.addEventListener('change', () => {
          const next = { disableCT: false, trustUserCAs: false, trustSystemCAs: false, ...hooks.get(pkg), [feature]: toggle.checked };
          if (next.disableCT || next.trustUserCAs || next.trustSystemCAs) hooks.set(pkg, next); else hooks.delete(pkg);
          expanded.add(pkg);
          renderApps(pkg, undefined, feature);
        });
        label.append(text, toggle);
        hookChoices.append(label);
        if (pkg === focusPackage && feature === focusHook) focusTarget = toggle;
      }
      row.append(summary, choices, hookChoices);
      fragment.append(row);
    }
    if (!visible.length) {
      const empty = document.createElement('p');
      empty.className = 'hint';
      empty.textContent = 'No apps found.';
      fragment.append(empty);
    }
    $('apps').replaceChildren(fragment);
    selectionChanged();
    if (focusTarget) focusTarget.focus();
  }

  function selectionChanged() {
    updateSave();
    $('selected-count').textContent = String(new Set([...assignments.keys(), ...hooks.keys()]).size);
    $('selection-note').textContent = 'Saving stops configured apps.';
    $('global-count').textContent = String(globalCertificates.size);
    $('global-note').textContent = 'All apps. Restart running apps after changes.';
    $('global-mode-note').hidden = ![...globalCertificates.values()].some(mode => mode !== 'system');
  }

  function renderGlobal() {
    closeChoice();
    const fragment = document.createDocumentFragment();
    for (const cert of certificates) {
      const label = document.createElement('label');
      label.className = 'certificate-choice';
      const select = modeSelect(cert, globalCertificates.get(cert.name), globalCertificates.get(cert.name), mode => {
        if (mode !== 'off') globalCertificates.set(cert.name, mode); else globalCertificates.delete(cert.name);
        select.title = mode === 'off' ? offHint : mode === 'both' ? 'System trust can still trigger WebView limits.' : mode === 'user' ? 'User trust requires app support.' : '';
        renderApps();
      });
      const text = document.createElement('span');
      const subject = document.createElement('strong');
      subject.textContent = certificateName(cert);
      const fingerprint = document.createElement('small');
      fingerprint.textContent = shortFingerprint(cert);
      text.append(subject, fingerprint);
      label.append(select, text);
      fragment.append(label);
    }
    if (!certificates.length) {
      const empty = document.createElement('p');
      empty.className = 'hint';
      empty.textContent = 'Add a certificate above to make it available to all apps.';
      fragment.append(empty);
    }
    $('global-certificates').replaceChildren(fragment);
  }

  function renderStatus(status, resetAssignments = false) {
    certificates = status.certificates;
    const savedAssignments = new Map(Object.entries(status.assignments).map(([key, modes]) => [key, new Map(Object.entries(modes))]));
    const savedGlobal = new Map(Object.entries(status.globalCertificates));
    const savedHooks = new Map(Object.entries(status.hooks).filter(([, flags]) => flags.disableCT === true || flags.trustUserCAs === true || flags.trustSystemCAs === true)
      .map(([key, flags]) => [key, { disableCT: flags.disableCT === true, trustUserCAs: flags.trustUserCAs === true, trustSystemCAs: flags.trustSystemCAs === true }]));
    savedPolicy = policyRecords(savedAssignments, savedGlobal, savedHooks);
    if (resetAssignments) {
      assignments.clear();
      for (const [pkg, modes] of savedAssignments) if (modes.size) assignments.set(pkg, modes);
      globalCertificates.clear();
      for (const [name, mode] of savedGlobal) globalCertificates.set(name, mode);
      hooks.clear();
      for (const [key, flags] of savedHooks) hooks.set(key, flags);
    } else {
      const valid = new Set(certificates.map(cert => cert.name));
      for (const name of globalCertificates.keys()) if (!valid.has(name)) globalCertificates.delete(name);
      for (const [pkg, names] of assignments) {
        for (const name of names.keys()) if (!valid.has(name)) names.delete(name);
        if (!names.size) assignments.delete(pkg);
      }
    }
    $('status').textContent = status.ready ? 'Ready' : 'Setup required';
    $('status-reason').textContent = status.reason || '';
    $('overview-apps').textContent = String(new Set([...savedAssignments.keys(), ...savedHooks.keys()]).size);
    $('overview-certs').textContent = String(certificates.length);
    $('overview-global').textContent = String(savedGlobal.size);
    $('log').textContent = status.log || 'The log is empty.';
    $('cert-count').textContent = String(status.certificates.length);
    const fragment = document.createDocumentFragment();
    for (const cert of status.certificates) {
      const li = document.createElement('li');
      li.className = 'certificate';
      const subject = document.createElement('strong');
      subject.textContent = certificateName(cert);
      const details = document.createElement('details');
      details.className = 'certificate-details';
      const summary = document.createElement('summary');
      summary.textContent = 'Certificate details';
      const distinguishedName = document.createElement('p');
      distinguishedName.textContent = cert.subject || cert.name;
      const fingerprint = document.createElement('small');
      fingerprint.textContent = 'SHA-256: ' + (cert.fingerprint || cert.name);
      details.append(summary, distinguishedName, fingerprint);
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = 'Delete';
      remove.setAttribute('aria-label', `Delete certificate ${certificateName(cert)}`);
      remove.addEventListener('click', () => {
        if (window.confirm(`Delete certificate ${certificateName(cert)}? It will be removed from individual and global assignments. Restart affected apps to clear their TLS caches.`)) run(async () => {
          await exec('remove-cert', cert.name);
          renderStatus(JSON.parse(await exec('status')));
        }, 'Deleting…', remove);
      });
      li.append(subject, details, remove);
      fragment.append(li);
    }
    if (!status.certificates.length) {
      const empty = document.createElement('li');
      empty.className = 'hint';
      empty.textContent = 'No additional certificates yet.';
      fragment.append(empty);
    }
    $('certificates').replaceChildren(fragment);
    renderGlobal();
    renderApps();
  }

  $('refresh').addEventListener('click', () => run(async () => {
    renderStatus(JSON.parse(await exec('status')));
  }, 'Refreshing…', $('refresh')));
  $('search').addEventListener('input', () => renderApps());
  const savePolicy = button => run(async () => {
    await exec('save-policy', policyRecords());
    renderStatus(JSON.parse(await exec('status')), true);
  }, 'Saving…', button);
  $('save').addEventListener('click', () => savePolicy($('save')));
  $('apply').addEventListener('click', () => run(async () => {
    await exec('apply');
    renderStatus(JSON.parse(await exec('status')));
  }, 'Applying…', $('apply')));
  $('add-certificate').addEventListener('click', () => { if (!busy && bridge) $('certificate').click(); });
  $('certificate').addEventListener('change', () => run(async () => {
    const file = $('certificate').files[0];
    if (!file) return;
    try {
      if (file.size === 0 || file.size > 65536) throw new Error('Choose a non-empty certificate up to 64 KiB.');
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      await exec('import-cert', btoa(binary));
      renderStatus(JSON.parse(await exec('status')));
    } finally { $('certificate').value = ''; }
  }, 'Importing…', $('add-certificate')));

  if (!bridge) {
    $('status').textContent = 'Open this page using the module WebUI button in KernelSU.';
    controls();
  } else run(async () => {
    const status = JSON.parse(await exec('status'));
    renderStatus(status, true);
    apps = JSON.parse(await exec('apps'));
    const profiles = new Map(apps.map(app => [app.userId || 0, profileName(app)]));
    $('profile-filter-wrap').hidden = profiles.size < 2;
    const options = [{ value: 'all', label: 'All profiles' }];
    for (const [id, label] of [...profiles].sort(([a], [b]) => a - b)) {
      options.push({ value: String(id), label });
    }
    configureChoice($('profile-filter'), options, 'all', () => renderApps());
    renderApps();
  }, 'Loading apps and certificates…');
})();
