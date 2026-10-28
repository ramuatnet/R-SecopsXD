/**
 * UI application logic. Vanilla ES module; talks to the same-origin API with
 * the operator token kept in sessionStorage (never a cookie — CSRF-safe by
 * construction, see docs/THREAT-MODEL.md).
 */

const API = {
  token: sessionStorage.getItem('ova_token') ?? '',
  async call(path, options = {}) {
    const res = await fetch(path, {
      ...options,
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.token}`,
        ...(options.headers ?? {}),
      },
    });
    if (res.status === 401) { showGate(); throw new Error('unauthorized'); }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.message ?? body.error ?? `${res.status}`);
    }
    return res.json();
  },
  async download(path, filename) {
    const res = await fetch(path, { headers: { authorization: `Bearer ${this.token}` } });
    if (!res.ok) throw new Error(`download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  },
};

// ---------- boot ----------

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

function showFormError(form, message) {
  let box = form.nextElementSibling;
  if (!box || !box.classList?.contains('form-error')) {
    box = el('div', 'form-error');
    form.after(box);
  }
  box.textContent = message;
  box.classList.remove('hidden');
}

function clearFormError(form) {
  const box = form.nextElementSibling;
  if (box?.classList?.contains('form-error')) box.classList.add('hidden');
}

function toast(msg, isError = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('hidden', false);
  t.style.borderColor = isError ? 'var(--high)' : 'var(--ok)';
  setTimeout(() => t.classList.add('hidden'), 3200);
}

function showGate() {
  $('#token-gate').classList.remove('hidden');
  $('#content').classList.add('hidden');
}

async function boot() {
  try {
    const h = await fetch('/api/health').then((r) => r.json());
    const health = $('#health');
    health.textContent = `online · v${h.version}`;
    health.classList.add('ok');
  } catch { $('#health').textContent = 'offline'; }

  if (!API.token) { showGate(); return; }
  try {
    await API.call('/api/profiles');
    enterApp();
  } catch { showGate(); }
}

function enterApp() {
  $('#token-gate').classList.add('hidden');
  $('#content').classList.remove('hidden');
  refreshAll();
}

$('#token-save')?.addEventListener('click', () => {
  API.token = $('#token-input').value.trim();
  sessionStorage.setItem('ova_token', API.token);
  API.call('/api/profiles')
    .then(() => { enterApp(); toast('Unlocked'); })
    .catch(() => $('#token-error').classList.remove('hidden'));
});
$('#token-input')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#token-save').click(); });

// ---------- navigation ----------

document.querySelectorAll('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
    $(`#view-${btn.dataset.view}`).classList.remove('hidden');
    refreshView(btn.dataset.view);
  });
});

function refreshAll() {
  refreshView('targets');
  refreshView('scans');
  refreshView('engines');
  refreshView('owasp');
  refreshView('audit');
}

function refreshView(view) {
  if (view === 'targets') loadTargets();
  if (view === 'scans') { loadTargetsIntoSelect(); loadProfiles(); loadScans(); }
  if (view === 'engines') loadEngines();
  if (view === 'owasp') loadOwasp();
  if (view === 'audit') loadAudit();
}

// ---------- targets ----------

async function loadTargets() {
  const { targets } = await API.call('/api/targets');
  const list = $('#target-list');
  list.textContent = '';
  if (targets.length === 0) list.append(el('div', 'muted', 'No targets registered yet.'));
  for (const t of targets) {
    const card = el('div', 'card');
    const row = el('div', 'row');
    row.append(el('span', 'title', t.name));
    row.append(el('span', 'badge', t.kind));
    row.append(t.approved ? el('span', 'badge ok', 'approved') : el('span', 'badge warn', 'not approved'));
    row.append(el('span', 'spacer'));
    if (!t.approved) {
      const approve = el('button', 'small approve', 'Approve');
      approve.addEventListener('click', async () => {
        await API.call(`/api/targets/${t.id}/approve`, { method: 'POST' });
        toast(`${t.name} approved (audited)`);
        loadTargets();
      });
      row.append(approve);
    }
    if (t.kind === 'webapp' && t.approved) {
      const credBtn = el('button', 'small', t.hasCredentials ? 'Update test account' : 'Set test account');
      credBtn.title = 'Configure a test account to unlock authenticated checks (logout invalidation, JWT forgery, surface mapping)';
      credBtn.addEventListener('click', async () => {
        const username = window.prompt(`Test account username for "${t.name}":`);
        if (!username) return;
        const password = window.prompt('Test account password (stored encrypted; never shown again):');
        if (!password) return;
        const loginUrl = window.prompt('Login form URL (optional — leave empty to use the crawled form):') ?? '';
        try {
          await API.call(`/api/targets/${t.id}/credentials`, {
            method: 'POST',
            body: JSON.stringify({ username, password, loginUrl: loginUrl || undefined }),
          });
          toast('Test account stored (encrypted)');
          loadTargets();
        } catch (err) { toast(err.message, true); }
      });
      row.append(credBtn);
    }
    card.append(row);
    card.append(el('div', 'sub', t.origin || t.sourcePath || ''));
    list.append(card);
  }
}

$('#target-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  clearFormError(e.target);
  try {
    await API.call('/api/targets', {
      method: 'POST',
      body: JSON.stringify({
        name: f.get('name'), kind: f.get('kind'),
        origin: f.get('origin') || undefined,
        sourcePath: f.get('sourcePath') || undefined,
      }),
    });
    e.target.reset();
    toast('Target registered — approve it to enable scanning');
    loadTargets();
  } catch (err) {
    showFormError(e.target, `Registration refused: ${err.message}`);
  }
});

// ---------- scans ----------

async function loadTargetsIntoSelect() {
  const { targets } = await API.call('/api/targets');
  const select = $('#scan-form [name=targetId]');
  select.textContent = '';
  for (const t of targets.filter((x) => x.approved)) {
    const opt = el('option', '', t.name);
    opt.value = t.id;
    select.append(opt);
  }
}

async function loadProfiles() {
  const { profiles } = await API.call('/api/profiles');
  const select = $('#scan-form [name=profile]');
  select.textContent = '';
  for (const p of profiles) {
    const opt = el('option', '', p.name);
    opt.value = p.id;
    select.append(opt);
  }
}

$('#scan-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  clearFormError(e.target);
  try {
    const { scan } = await API.call('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ targetId: f.get('targetId'), profile: f.get('profile'), mode: f.get('mode') }),
    });
    toast(`Scan ${scan.id.slice(0, 8)} started`);
    setTimeout(loadScans, 400);
  } catch (err) {
    showFormError(e.target, `Scan not started: ${err.message}`);
  }
});

async function loadScans() {
  const { scans } = await API.call('/api/scans');
  const wrap = $('#scan-list');
  wrap.textContent = '';
  const table = el('table');
  table.append(el('tr', '', ''));
  const head = el('tr');
  for (const h of ['Status', 'Target', 'Profile', 'Mode', 'Findings', 'Started', '']) head.append(el('th', '', h));
  table.append(head);
  for (const s of scans.slice(0, 25)) {
    const tr = el('tr');
    const status = el('td');
    status.append(el('span', `badge ${s.status === 'completed' ? 'ok' : s.status === 'running' ? 'warn' : ''}`, s.status));
    tr.append(status);
    tr.append(el('td', '', s.targetName));
    tr.append(el('td', '', s.profile));
    tr.append(el('td', '', s.mode));
    tr.append(el('td', '', String(s.stats?.totalFindings ?? 0)));
    tr.append(el('td', '', new Date(s.startedAt).toLocaleString()));
    const actions = el('td');
    const view = el('button', 'small', 'View');
    view.addEventListener('click', () => showScan(s.id));
    actions.append(view);
    if (s.status === 'running' || s.status === 'queued') {
      const cancel = el('button', 'small', 'Cancel');
      cancel.addEventListener('click', async () => {
        await API.call(`/api/scans/${s.id}/cancel`, { method: 'POST' });
        toast('Cancellation requested');
        setTimeout(loadScans, 300);
      });
      actions.append(cancel);
    }
    tr.append(actions);
    table.append(tr);
  }
  wrap.append(table);
}

const SEV_CLASS = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

async function showScan(scanId) {
  const { scan, findings } = await API.call(`/api/scans/${scanId}`);
  const detail = $('#scan-detail');
  detail.textContent = '';

  const head = el('div', 'panel');
  head.append(el('h2', '', `Scan ${scan.id.slice(0, 8)} — ${scan.targetName}`));
  head.append(el('div', 'sub', `${scan.profile} · ${scan.mode} · ${scan.status} · ${scan.stats.requestsSent} requests sent, ${scan.stats.requestsBlocked} blocked by safety layer`));

  const engineTable = el('table');
  const ehead = el('tr');
  for (const h of ['Engine', 'Status', 'Findings', 'Duration', 'Detail']) ehead.append(el('th', '', h));
  engineTable.append(ehead);
  for (const e of scan.engines) {
    const tr = el('tr');
    tr.append(el('td', '', e.engine));
    const st = el('td');
    st.append(el('span', `badge ${e.status === 'ran' ? 'ok' : e.status === 'unavailable' || e.status === 'failed' ? 'warn' : ''}`, e.status));
    tr.append(st);
    tr.append(el('td', '', String(e.findingCount)));
    tr.append(el('td', '', `${e.durationMs} ms`));
    tr.append(el('td', 'sub', e.detail ?? (e.version ?? '')));
    engineTable.append(tr);
  }
  head.append(engineTable);

  const covTitle = el('h2', '', 'OWASP Top 10:2025 coverage');
  head.append(covTitle);
  const cov = el('table', 'coverage');
  const chead = el('tr');
  for (const h of ['Category', 'Verdict', 'Engines', 'Notes & limits']) chead.append(el('th', '', h));
  cov.append(chead);
  for (const c of scan.coverage) {
    const tr = el('tr', c.verdict === 'manual-only' ? 'cov-manual-only' : '');
    const cat = el('td');
    cat.append(el('span', 'badge cat', `${c.category}`));
    cat.append(document.createTextNode(` ${CATEGORY_NAMES[c.category] ?? ''}`));
    tr.append(cat);
    const verdict = el('td');
    verdict.append(el('span', `badge ${c.verdict === 'covered' ? 'ok' : c.verdict === 'partial' ? 'warn' : ''}`, c.verdict));
    tr.append(verdict);
    tr.append(el('td', '', c.engines.join(', ') || '—'));
    tr.append(el('td', 'sub', c.note));
    cov.append(tr);
  }
  head.append(cov);
  detail.append(head);

  const findingsPanel = el('div', 'panel');
  findingsPanel.append(el('h2', '', `Findings (${findings.length})`));
  const table = el('table');
  const fhead = el('tr');
  for (const h of ['Severity', 'Title', 'Category', 'Status', 'Confidence', 'Locator']) fhead.append(el('th', '', h));
  table.append(fhead);
  for (const f of findings) {
    const tr = el('tr', 'finding-row');
    const sev = el('td');
    sev.append(el('span', `badge ${SEV_CLASS[f.severity] ?? 'info'}`, f.severity));
    tr.append(sev);
    tr.append(el('td', '', f.title));
    tr.append(el('td', '', f.category));
    const status = el('td');
    status.append(el('span', `badge ${f.status === 'false_positive' ? '' : 'ok'}`, f.status));
    tr.append(status);
    tr.append(el('td', '', f.confidence));
    tr.append(el('td', '', f.locator));
    tr.addEventListener('click', () => toggleFindingDetail(tr, f, scan.id));
    table.append(tr);
  }
  findingsPanel.append(table);
  detail.append(findingsPanel);

  const diffPanel = el('div', 'panel');
  diffPanel.append(el('h2', '', 'Rescan diff'));
  const diffBtn = el('button', 'small', 'Compare with previous scan of this target');
  diffBtn.addEventListener('click', async () => {
    try {
      const d = await API.call(`/api/targets/${scan.targetId}/diff?to=${scan.id}`);
      diffPanel.querySelectorAll('.diff-result').forEach((n) => n.remove());
      const out = el('div', 'diff-result');
      out.append(el('p', 'sub', `${d.summary.added} new · ${d.summary.removed} fixed · ${d.summary.unchanged} persistent (vs scan ${d.fromScan.id.slice(0, 8)})`));
      const list = (items, cls, label) => {
        if (items.length === 0) return;
        const h = el('h4', '', `${label} (${items.length})`);
        out.append(h);
        for (const f of items) {
          const row = el('div', 'row');
          row.append(el('span', `badge ${cls}`, f.severity));
          row.append(el('span', '', f.title));
          out.append(row);
        }
      };
      list(d.added, 'high', 'New since previous scan');
      list(d.removed, 'ok', 'No longer observed (fixed or surface changed)');
      list(d.unchanged, '', 'Persistent');
      diffPanel.append(out);
    } catch (err) { toast(err.message, true); }
  });
  diffPanel.append(diffBtn);
  detail.append(diffPanel);

  const reports = el('div', 'panel');
  reports.append(el('h2', '', 'Reports'));
  const row = el('div', 'row');
  for (const fmt of ['json', 'html', 'pdf']) {
    const btn = el('button', 'small', `Download ${fmt.toUpperCase()}`);
    btn.addEventListener('click', () => API.download(`/api/scans/${scan.id}/report?format=${fmt}`, `assessment-${scan.id.slice(0, 8)}.${fmt}`).catch((e) => toast(e.message, true)));
    row.append(btn);
  }
  reports.append(row);
  detail.append(reports);

  detail.scrollIntoView({ behavior: 'smooth' });
}

const CATEGORY_NAMES = {
  A01: 'Broken Access Control', A02: 'Security Misconfiguration', A03: 'Software Supply Chain Failures',
  A04: 'Cryptographic Failures', A05: 'Injection', A06: 'Insecure Design',
  A07: 'Authentication Failures', A08: 'Software or Data Integrity Failures',
  A09: 'Security Logging and Alerting Failures', A10: 'Mishandling of Exceptional Conditions',
};

function toggleFindingDetail(tr, f, scanId) {
  const existing = tr.nextElementSibling;
  if (existing?.classList?.contains('finding-detail-row')) { existing.remove(); return; }
  const detailRow = el('tr', 'finding-detail-row');
  const cell = el('td');
  cell.colSpan = 6;
  const detail = el('div', 'finding-detail');
  detail.append(el('div', 'sub', `${f.id} · CWE-${f.cwe ?? '—'}${f.cve ? ` · ${f.cve}` : ''} · engines: ${f.provenance.map((p) => `${p.engine}${p.rawId ? ` (${p.rawId})` : ''}`).join(', ')}`));
  detail.append(el('p', '', f.explanation));
  const rem = el('p');
  rem.style.color = 'var(--ok)';
  rem.textContent = `Remediation: ${f.remediation}`;
  detail.append(rem);
  for (const ev of f.evidence) {
    const pre = el('pre', 'evidence');
    pre.textContent = evidenceText(ev);
    detail.append(pre);
  }
  const triage = el('div', 'row');
  for (const [label, status] of [['Mark false positive', 'false_positive'], ['Mark confirmed', 'confirmed']]) {
    const btn = el('button', 'small', label);
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      await API.call(`/api/scans/${scanId}/findings/${f.id}/status`, {
        method: 'POST', body: JSON.stringify({ status }),
      }).catch((err) => toast(err.message, true));
      toast(`Triage saved: ${status} (applies to future scans too)`);
    });
    triage.append(btn);
  }
  detail.append(triage);
  cell.append(detail);
  detailRow.append(cell);
  tr.after(detailRow);
}

function evidenceText(ev) {
  switch (ev.kind) {
    case 'http': {
      const req = `REQUEST ${ev.request.method} ${ev.request.url}`;
      const resp = ev.response ? `\nRESPONSE ${ev.response.status}\n${ev.response.bodyExcerpt ?? ''}` : '';
      return `${req}${resp}\n${ev.observation}`;
    }
    case 'file': return `${ev.path}${ev.lineStart ? `:${ev.lineStart}` : ''}\n${ev.excerpt ?? ''}\n${ev.observation}`;
    case 'process': return `$ ${ev.command}\n${ev.stdoutExcerpt ?? ''}\n${ev.observation}`;
    case 'dependency': return `${ev.ecosystem}: ${ev.packageName}${ev.installedVersion ? `@${ev.installedVersion}` : ''}\n${ev.observation}`;
    default: return JSON.stringify(ev, null, 2);
  }
}

// ---------- engines ----------

async function loadEngines() {
  const { engines } = await API.call('/api/engines');
  const list = $('#engine-list');
  list.textContent = '';
  for (const e of engines) {
    const card = el('div', 'card');
    const row = el('div', 'row');
    row.append(el('span', 'title', e.name));
    row.append(el('span', 'badge', e.kind));
    if (e.availability.available) {
      row.append(el('span', 'badge ok', e.availability.version ?? 'available'));
    } else {
      row.append(el('span', 'badge warn', 'unavailable'));
    }
    row.append(el('span', 'spacer'));
    card.append(row);
    if (!e.availability.available && e.availability.reason) {
      card.append(el('div', 'sub', e.availability.reason));
    }
    if (!e.availability.available && e.availability.installHint) {
      card.append(el('div', 'sub', `Install: ${e.availability.installHint}`));
    }
    const caps = Object.entries(e.capabilities ?? {});
    if (caps.length > 0) {
      card.append(el('div', 'sub', caps.map(([c, cap]) => `${c}: ${cap.note}${cap.strength === 'heuristic' ? ' (heuristic)' : ''}`).join(' · ')));
    }
    list.append(card);
  }
}

// ---------- owasp ----------

async function loadOwasp() {
  const { categories } = await API.call('/api/owasp');
  const list = $('#owasp-list');
  list.textContent = '';
  for (const c of categories) {
    const card = el('div', 'card');
    const row = el('div', 'row');
    row.append(el('span', 'badge cat', c.code));
    row.append(el('span', 'title', c.name));
    row.append(el('span', 'spacer'));
    const link = el('a', 'sub', 'reference ↗');
    link.href = c.reference;
    link.target = '_blank';
    link.rel = 'noopener';
    row.append(link);
    card.append(row);
    card.append(el('div', 'sub', c.summary));
    card.append(el('div', 'sub', `Automation limits: ${c.automation}`));
    list.append(card);
  }
}

// ---------- audit ----------

async function loadAudit() {
  const { entries } = await API.call('/api/audit');
  const wrap = $('#audit-list');
  wrap.textContent = '';
  const table = el('table');
  const head = el('tr');
  for (const h of ['Time', 'Actor', 'Action', 'Details']) head.append(el('th', '', h));
  table.append(head);
  for (const e of entries) {
    const tr = el('tr');
    tr.append(el('td', '', new Date(e.ts).toLocaleString()));
    tr.append(el('td', '', e.actor));
    tr.append(el('td', '', e.action));
    tr.append(el('td', 'sub', e.details ? JSON.stringify(e.details) : ''));
    table.append(tr);
  }
  wrap.append(table);
}

boot();
