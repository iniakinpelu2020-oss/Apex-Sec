/* Apex-Sec — module logic: recon, payload/encoder, hashes, reporting, toolset.
   Loaded after core.js, which provides $, el, toast, copy and tab routing.
   Everything here runs in the tab; nothing is uploaded anywhere. */

'use strict';

const TE = new TextEncoder();
const TD = new TextDecoder();

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const bytesOf = (text) => TE.encode(text);

/* ------------------------------------------------------------- target intake */

function parseTarget(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;

  // "host", "host:port", "https://host/path" all become a fetchable URL.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : 'https://' + value;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (!url.hostname) return null;
  return url;
}

function hostLabel(url) {
  const port = url.port ? ':' + url.port : '';
  return url.hostname + port;
}

async function probeTarget() {
  const input = $('target');
  const card = $('probeCard');
  const out = $('probeOut');
  const badge = $('probeBadge');
  const note = $('probeNote');
  const hint = $('targetHint');
  if (!input || !out) return;

  const url = parseTarget(input.value);
  if (!url) {
    hint.textContent = 'That does not look like a host or URL. Try example.com or https://example.com/path.';
    hint.classList.add('bad');
    return;
  }
  hint.classList.remove('bad');
  hint.textContent = 'Probing ' + hostLabel(url) + ' …';

  card.hidden = false;
  out.textContent = '';
  note.textContent = '';
  badge.className = 'badge';
  badge.textContent = 'probing';

  const started = performance.now();
  let res = null;
  let error = null;

  try {
    res = await fetch(url.href, { mode: 'cors', cache: 'no-store', redirect: 'follow' });
  } catch (e) {
    // A CORS failure still proves DNS, TCP and TLS completed: the request left
    // and something answered, the browser just refuses to hand over the body.
    error = e;
  }
  const elapsed = Math.round(performance.now() - started);

  const rows = [];
  rows.push(['Target', url.href]);

  if (res) {
    let readableHeaders = 0;
    try {
      readableHeaders = [...res.headers.keys()].length;
    } catch {
      readableHeaders = 0;
    }
    const opaque = res.type === 'opaque' || res.type === 'opaqueredirect';

    rows.push(['Status', res.ok ? res.status + ' ' + (res.statusText || 'OK') : String(res.status)]);
    rows.push(['Response type', res.type]);
    rows.push(['Round trip', elapsed + ' ms']);
    rows.push(['Final URL', res.url || url.href]);
    rows.push(['Headers readable', opaque ? 'no — the target did not opt in' : readableHeaders + ' readable']);

    if (opaque) {
      badge.className = 'badge warn';
      badge.textContent = 'opaque';
      note.textContent =
        'The host answered, so DNS, TCP and TLS all worked. The browser hides the status and ' +
        'headers because the response carried no Access-Control-Allow-Origin. Paste the output of ' +
        'curl -sSI into the header box below to audit them.';
    } else {
      badge.className = 'badge ok';
      badge.textContent = res.ok ? 'reachable' : 'error status';
      note.textContent = res.ok
        ? 'CORS-readable response: the status, headers and timing below are real, not guessed.'
        : 'The host answered with an error status. That is still a live host; the header audit below still applies.';

      // Feed the live headers straight into the audit so nothing is retyped.
      const live = ['HTTP ' + res.status];
      try {
        res.headers.forEach((v, k) => live.push(k + ': ' + v));
      } catch {
        /* opaque after all */
      }
      if (live.length > 1) runHeaderAudit(live.join('\n'), true);
    }
  } else {
    badge.className = 'badge bad';
    badge.textContent = 'blocked';
    rows.push(['Round trip', elapsed + ' ms (failure after the request left)']);
    rows.push(['Reported as', (error && error.name) || 'network error']);
    note.textContent =
      'The fetch failed. A browser cannot tell "host is down" from "CORS blocked the read" or ' +
      '"mixed content blocked the request", so this console does not pretend to. If the host is up ' +
      'in a terminal, the failure is CORS; paste curl -sSI output below to audit headers.';
  }

  rows.forEach(([k, v]) => {
    out.appendChild(el('dt', null, k));
    out.appendChild(el('dd', null, v));
  });

  hint.textContent = 'Accepts a bare host, host:port, or a full URL.';
}

function copyCurl() {
  const url = parseTarget($('target') && $('target').value);
  if (!url) {
    toast('Enter a target first');
    return;
  }
  copy("curl -sSI '" + url.href + "'", 'curl command copied');
}

/* ------------------------------------------------------------ header auditing */

const HEADER_CHECKS = [
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    run: (v) => (v ? { state: 'pass', note: 'HSTS present: ' + v } : { state: 'fail', note: 'Missing: the site can be downgraded to plain HTTP.' }),
  },
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    run: (v) => {
      if (!v) return { state: 'fail', note: 'Missing: no defence in depth against injected scripts.' };
      if (/'unsafe-inline'/i.test(v)) return { state: 'warn', note: "Present but allows 'unsafe-inline', so inline script injection is not blocked." };
      if (/'unsafe-eval'/i.test(v)) return { state: 'warn', note: "Present but allows 'unsafe-eval'." };
      return { state: 'pass', note: 'Present without unsafe-inline or unsafe-eval.' };
    },
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    run: (v) => (/nosniff/i.test(v || '') ? { state: 'pass', note: 'nosniff set.' } : { state: 'warn', note: 'Missing or not nosniff: browsers may MIME-sniff responses.' }),
  },
  {
    key: 'x-frame-options',
    label: 'Frame protection',
    run: (v, headers) => {
      const csp = headers['content-security-policy'] || '';
      if (/deny|sameorigin/i.test(v || '')) return { state: 'pass', note: 'X-Frame-Options: ' + v };
      if (/frame-ancestors/i.test(csp)) return { state: 'pass', note: "No X-Frame-Options, but CSP frame-ancestors covers it: " + csp.match(/frame-ancestors[^;]*/i)[0] };
      return { state: 'warn', note: 'Neither X-Frame-Options nor CSP frame-ancestors: the page can be framed (clickjacking).' };
    },
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    run: (v) => (v ? { state: 'pass', note: 'Referrer-Policy: ' + v } : { state: 'warn', note: 'Missing: full URLs can leak to third parties.' }),
  },
  {
    key: 'permissions-policy',
    label: 'Permissions-Policy',
    run: (v) => (v ? { state: 'pass', note: 'Permissions-Policy: ' + v } : { state: 'warn', note: 'Missing: browser features are not explicitly disabled.' }),
  },
  {
    key: 'access-control-allow-origin',
    label: 'CORS',
    run: (v) => {
      if (!v) return { state: 'pass', note: 'No CORS header, so other origins cannot read responses.' };
      if (v.trim() === '*') return { state: 'warn', note: "Wildcard Access-Control-Allow-Origin: any site can read this response." };
      return { state: 'pass', note: 'Scoped Access-Control-Allow-Origin: ' + v };
    },
  },
  {
    key: 'server',
    label: 'Server disclosure',
    run: (v) => (v ? { state: 'warn', note: 'Server header discloses: ' + v } : { state: 'pass', note: 'No Server header.' }),
  },
  {
    key: 'x-powered-by',
    label: 'Stack disclosure',
    run: (v) => (v ? { state: 'warn', note: 'X-Powered-By discloses: ' + v } : { state: 'pass', note: 'No X-Powered-By header.' }),
  },
];

function parseHeaderBlock(text) {
  const headers = {};
  let status = '';
  String(text || '')
    .split(/\r?\n/)
    .forEach((line, i) => {
      if (!line.trim()) return;
      if (i === 0 && /^HTTP\//i.test(line.trim())) {
        status = line.trim();
        return;
      }
      const at = line.indexOf(':');
      if (at < 1) return;
      headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
    });
  return { status, headers };
}

function runHeaderAudit(text, fromLive) {
  const target = $('headerReport');
  if (!target) return;
  const { status, headers } = parseHeaderBlock(text);
  const names = Object.keys(headers);

  target.textContent = '';
  target.hidden = false;

  if (!names.length) {
    target.hidden = true;
    toast('No headers found in that text');
    return;
  }

  const summary = el('div', 'hrow');
  summary.appendChild(el('span', 'hname', (fromLive ? 'Live response' : 'Pasted response') + (status ? ' · ' + status : '')));
  const count = HEADER_CHECKS.reduce(
    (acc, c) => {
      const r = c.run(headers[c.key], headers);
      acc[r.state] = (acc[r.state] || 0) + 1;
      return acc;
    },
    { pass: 0, warn: 0, fail: 0 }
  );
  const verdict = el('span', 'badge ' + (count.fail ? 'bad' : count.warn ? 'warn' : 'ok'), count.fail ? count.fail + ' fail' : count.warn ? count.warn + ' warn' : 'clean');
  summary.appendChild(verdict);
  summary.appendChild(el('span', 'hnote', count.pass + ' passing · ' + count.warn + ' to review · ' + count.fail + ' missing, across ' + names.length + ' headers'));
  target.appendChild(summary);

  HEADER_CHECKS.forEach((check) => {
    const result = check.run(headers[check.key], headers);
    const row = el('div', 'hrow ' + result.state);
    row.appendChild(el('span', 'hname', check.label));
    row.appendChild(el('span', 'badge ' + (result.state === 'pass' ? 'ok' : result.state === 'warn' ? 'warn' : 'bad'), result.state));
    row.appendChild(el('span', 'hnote', result.note));
    target.appendChild(row);
  });
}

/* --------------------------------------------------------- ports → nmap/curl */

function generateNmap() {
  const url = parseTarget($('target') && $('target').value);
  if (!url) {
    toast('Enter a target first');
    return;
  }
  const ports = String(($('portList') && $('portList').value) || '')
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (!ports.length) {
    toast('Add at least one port');
    return;
  }
  const bad = ports.filter((p) => !/^\d{1,5}(-\d{1,5})?$/.test(p));
  if (bad.length) {
    toast('Not a port: ' + bad[0]);
    return;
  }

  const host = url.hostname;
  const command = 'nmap -sV -Pn -p ' + ports.join(',') + ' ' + host;
  const out = $('nmapOut');
  out.textContent = command;
  out.hidden = false;
  $('nmapActions').hidden = false;

  // Same host, one line per port, for anything that prefers curl to nmap.
  const curls = ports
    .map((p) => "curl -sSI --max-time 5 'https://" + host + ':' + p + "/' | head -n 1")
    .join('\n');
  copy(command, 'nmap command copied');
  console.info('Apex-Sec · curl equivalents\n' + curls);
}

/* ------------------------------------------------------------- payload tools */

const b64Std = (s) => btoa(String.fromCharCode(...bytesOf(s)));
const b64Url = (s) => b64Std(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function fromB64(s) {
  const clean = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  return TD.decode(Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)));
}

function reverseText(s) {
  return [...s].reverse().join('');
}

const TRANSFORMS = {
  b64enc: (s) => b64Std(s),
  b64dec: (s) => fromB64(s),
  b64url: (s) => b64Url(s),
  urlenc: (s) => encodeURIComponent(s),
  urldec: (s) => decodeURIComponent(s),
  hex: (s) => toHex(bytesOf(s)),
  reverse: (s) => reverseText(s),
  clear: () => '',
};

function applyTransform(kind) {
  const input = $('payloadIn');
  const out = $('payloadOut');
  if (!input || !out) return;
  const fn = TRANSFORMS[kind];
  if (!fn) return;
  try {
    const value = fn(input.value);
    out.textContent = value;
    if (kind === 'clear') {
      input.value = '';
      toast('Cleared');
    }
  } catch (e) {
    toast(kind === 'b64dec' ? 'Not valid Base64' : 'That input could not be decoded');
  }
}

const SNIPPETS = {
  sqli: [
    "' OR '1'='1' --",
    "admin'--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(5)--",
  ],
  xss: [
    '<script>alert(document.domain)</script>',
    '"><img src=x onerror=alert(document.domain)>',
    "javascript:alert(document.domain)",
    '<svg onload=alert(document.domain)>',
  ],
  traversal: [
    '../../../../etc/passwd',
    '....//....//etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
  ],
  ssrf: [
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:80/admin',
    'http://[::1]:8080/',
    'file:///etc/passwd',
  ],
  redirect: [
    'https://trusted.example.com/?next=https://evil.example',
    '//evil.example',
    '/\\evil.example',
  ],
};

function showSnippet(kind) {
  const box = $('snippetOut');
  const list = SNIPPETS[kind];
  if (!box || !list) return;
  box.textContent = list.map((s) => '· ' + s).join('\n');
  box.hidden = false;
}

/* ------------------------------------------------------------------- hashes */

function md5(text) {
  const msg = bytesOf(text);
  const len = msg.length;
  const bitLen = len * 8;
  const buffer = new Uint8Array((((len + 8) >> 6) + 1) * 64);
  buffer.set(msg);
  buffer[len] = 0x80;
  const view = new DataView(buffer.buffer);
  view.setUint32(buffer.length - 8, bitLen >>> 0, true);
  view.setUint32(buffer.length - 4, Math.floor(bitLen / 0x100000000), true);

  const shift = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < buffer.length; offset += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(offset + i * 4, true);

    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let F;
      let g;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + (((F << shift[i]) | (F >>> (32 - shift[i]))) >>> 0)) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((word) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, word, true);
      return toHex(bytes);
    })
    .join('');
}

async function generateHashes() {
  const grid = $('hashGrid');
  const input = $('payloadIn');
  if (!grid || !input) return;
  const text = input.value;
  if (!text) {
    toast('Nothing to hash');
    return;
  }

  grid.textContent = '';
  const rows = [['MD5', md5(text)]];

  if (window.crypto && crypto.subtle) {
    try {
      for (const name of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
        const digest = await crypto.subtle.digest(name, bytesOf(text));
        rows.push([name, toHex(new Uint8Array(digest))]);
      }
    } catch {
      toast('WebCrypto refused to hash here');
    }
  } else {
    // crypto.subtle needs a secure origin; say so instead of showing nothing.
    const row = el('div', 'hrow warn');
    row.appendChild(el('span', 'hname', 'SHA family unavailable'));
    row.appendChild(el('span', 'badge warn', 'no WebCrypto'));
    row.appendChild(el('span', 'hnote', 'crypto.subtle requires HTTPS or localhost. MD5 above still works.'));
    grid.appendChild(row);
  }

  rows.forEach(([name, value]) => {
    const row = el('div', 'hash-row');
    row.appendChild(el('span', null, name));
    const v = el('span', null, value);
    v.title = 'Click to copy';
    v.style.cursor = 'pointer';
    v.addEventListener('click', () => copy(value, name + ' copied'));
    row.appendChild(v);
    grid.appendChild(row);
  });
}

/* ------------------------------------------------------------------- report */

const REPORT_FIELDS = ['rTitle', 'rTarget', 'rSeverity', 'rCvss', 'rEndpoint', 'rHeaders', 'rSteps', 'rImpact', 'rFix'];
const DRAFT_KEY = 'apex-sec-report-v1';

function readField(id) {
  const node = $(id);
  return node ? String(node.value || '').trim() : '';
}

function severityRank(sev) {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  return order.indexOf(sev) >= 0 ? order.indexOf(sev) : 2;
}

function buildReportMarkdown() {
  const title = readField('rTitle') || 'Untitled finding';
  const target = readField('rTarget') || '(asset not set)';
  const severity = readField('rSeverity') || 'High';
  const cvss = readField('rCvss');
  const endpoint = readField('rEndpoint');
  const headers = readField('rHeaders');
  const steps = readField('rSteps');
  const impact = readField('rImpact');
  const fix = readField('rFix');

  const lines = [];
  lines.push('# ' + title);
  lines.push('');
  lines.push('**Severity:** ' + severity + (cvss ? ' · CVSS 3.1 ' + cvss : ''));
  if (severityRank(severity) <= 1) lines.push('**Priority:** report promptly; this is a high-impact class of bug.');
  lines.push('');
  lines.push('## Asset');
  lines.push('');
  lines.push('`' + target + '`');
  lines.push('');
  if (endpoint) {
    lines.push('## Vulnerable endpoint');
    lines.push('');
    lines.push('```http');
    lines.push(endpoint);
    lines.push('```');
    lines.push('');
  }
  if (headers) {
    lines.push('## Request');
    lines.push('');
    lines.push('```http');
    lines.push(headers);
    lines.push('```');
    lines.push('');
  }
  lines.push('## Steps to reproduce');
  lines.push('');
  if (steps) {
    steps.split(/\r?\n/).filter(Boolean).forEach((line, i) => lines.push(i + 1 + '. ' + line.trim()));
  } else {
    lines.push('1. (describe the first step)');
  }
  lines.push('');
  lines.push('## Impact');
  lines.push('');
  lines.push(impact || '(state what an attacker gains, and whose data or accounts are affected.)');
  lines.push('');
  lines.push('## Remediation');
  lines.push('');
  lines.push(fix || '(state the concrete fix, and any defence in depth.)');
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  lines.push('- Tested manually against a system I am authorised to test.');
  lines.push('- No data was modified or exfiltrated beyond what the proof of concept needed.');
  lines.push('');
  return lines.join('\n');
}

let reportTimer = null;

function renderReport() {
  const out = $('reportOut');
  if (!out) return;
  out.textContent = buildReportMarkdown();

  clearTimeout(reportTimer);
  reportTimer = setTimeout(() => {
    const draft = {};
    REPORT_FIELDS.forEach((id) => {
      draft[id] = readField(id);
    });
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
    } catch {
      /* private mode: drafts simply do not persist */
    }
  }, 300);
}

function hydrateReport() {
  let draft = null;
  try {
    draft = JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null');
  } catch {
    draft = null;
  }
  if (draft) {
    REPORT_FIELDS.forEach((id) => {
      const node = $(id);
      if (node && typeof draft[id] === 'string') node.value = draft[id];
    });
  }
  renderReport();
}

function downloadReport() {
  const markdown = buildReportMarkdown();
  const slug = (readField('rTitle') || 'apex-sec-finding')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60) || 'apex-sec-finding';
  const blob = new Blob([markdown], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const link = el('a');
  link.href = url;
  link.download = slug + '.md';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  toast('Report downloaded');
}

/* ------------------------------------------------------------------ toolset */

const TOOLS = [
  {
    name: 'Nmap',
    role: 'Network mapping',
    desc: 'The real port scanner. A browser cannot open raw sockets, so this is where the port list above actually runs.',
    cmd: 'nmap -sV -Pn -p 22,80,443 <host>',
    url: 'https://nmap.org/book/man.html',
  },
  {
    name: 'Burp Suite',
    role: 'Intercepting proxy',
    desc: 'Captures and rewrites requests so a payload can be replayed with exact headers. Community edition is free.',
    cmd: 'burpsuite --use-defaults  # set the browser proxy to 127.0.0.1:8080',
    url: 'https://portswigger.net/burp/documentation',
  },
  {
    name: 'Metasploit',
    role: 'Exploit framework',
    desc: 'Verifies an exposure with a known module once recon says the service is there.',
    cmd: 'msfconsole -q  # then: search <service>',
    url: 'https://docs.metasploit.com/',
  },
  {
    name: 'Wireshark',
    role: 'Packet analysis',
    desc: 'Proves what actually crossed the wire, which is often the difference between a guess and a finding.',
    cmd: 'tshark -i any -f "host <host>"',
    url: 'https://www.wireshark.org/docs/',
  },
  {
    name: 'SQLmap',
    role: 'Injection probing',
    desc: 'Run it only against a parameter you are authorised to attack. Keep --batch off so it is deliberate.',
    cmd: "sqlmap -u 'https://<host>/item?id=1' --technique=BEUST",
    url: 'https://github.com/sqlmapproject/sqlmap/wiki/Usage',
  },
  {
    name: 'Your own scripts',
    role: 'Automation',
    desc: 'Every nmap command generated above can be pasted into a loop. Keep the evidence the report needs as you go.',
    cmd: 'for h in $(cat targets.txt); do nmap -sV -Pn $h; done',
    url: 'https://owasp.org/www-project-web-security-testing-guide/',
  },
];

function renderTools() {
  const grid = $('toolGrid');
  if (!grid) return;
  grid.textContent = '';
  TOOLS.forEach((tool) => {
    const card = el('div', 'tool');
    card.appendChild(el('span', 'role', tool.role));
    card.appendChild(el('h4', null, tool.name));
    card.appendChild(el('p', null, tool.desc));
    card.appendChild(el('code', null, tool.cmd));

    const actions = el('div', 'tool-actions');
    const copyBtn = el('button', 'mini', 'Copy');
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', () => copy(tool.cmd, tool.name + ' command copied'));
    actions.appendChild(copyBtn);

    const docs = el('a', 'mini', 'Docs');
    docs.href = tool.url;
    docs.target = '_blank';
    docs.rel = 'noopener noreferrer';
    actions.appendChild(docs);

    card.appendChild(actions);
    grid.appendChild(card);
  });
}

/* ------------------------------------------------------------ install + boot */

let installEvent = null;

function wireInstall() {
  const btn = $('installBtn');
  if (!btn) return;
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    installEvent = event;
    btn.hidden = false;
  });
  btn.addEventListener('click', async () => {
    if (!installEvent) return;
    installEvent.prompt();
    const choice = await installEvent.userChoice.catch(() => null);
    installEvent = null;
    btn.hidden = true;
    if (choice && choice.outcome === 'accepted') toast('Installed');
  });
  window.addEventListener('appinstalled', () => {
    btn.hidden = true;
    toast('Apex-Sec installed');
  });
}

function boot() {
  // Recon
  const probeBtn = $('probeBtn');
  if (probeBtn) probeBtn.addEventListener('click', probeTarget);
  const target = $('target');
  if (target) {
    target.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') probeTarget();
    });
  }
  const copyCurlBtn = $('copyCurl');
  if (copyCurlBtn) copyCurlBtn.addEventListener('click', copyCurl);
  const parseBtn = $('parseHeaders');
  if (parseBtn) {
    parseBtn.addEventListener('click', () => {
      const box = $('headerInput');
      if (!box || !box.value.trim()) {
        toast('Paste a header block first');
        return;
      }
      runHeaderAudit(box.value, false);
    });
  }
  const nmapBtn = $('genNmap');
  if (nmapBtn) nmapBtn.addEventListener('click', generateNmap);

  // Payload
  document.querySelectorAll('[data-transform]').forEach((btn) => {
    btn.addEventListener('click', () => applyTransform(btn.dataset.transform));
  });
  const hashBtn = $('hashBtn');
  if (hashBtn) hashBtn.addEventListener('click', generateHashes);
  document.querySelectorAll('[data-snippet]').forEach((btn) => {
    btn.addEventListener('click', () => showSnippet(btn.dataset.snippet));
  });

  // Copy buttons that name their source element.
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const node = $(btn.dataset.copy);
      copy(node ? node.textContent : '', 'Copied');
    });
  });

  // Report
  REPORT_FIELDS.forEach((id) => {
    const node = $(id);
    if (!node) return;
    node.addEventListener('input', renderReport);
    node.addEventListener('change', renderReport);
  });
  const copyReport = $('copyReport');
  if (copyReport) copyReport.addEventListener('click', () => copy(buildReportMarkdown(), 'Report copied'));
  const download = $('downloadReport');
  if (download) download.addEventListener('click', downloadReport);
  hydrateReport();

  // Toolset
  renderTools();

  // Install + offline shell
  wireInstall();
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('sw.js').catch(() => {
      toast('Offline shell unavailable in this browser');
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
