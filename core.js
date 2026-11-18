/* Apex-Sec — shared helpers, tab routing and network state.
   Loaded first; every other module builds on these. */

'use strict';

/* ------------------------------------------------------------------ utils */

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

let toastTimer = null;
function toast(message) {
  let node = document.querySelector('.toast');
  if (!node) {
    node = el('div', 'toast');
    document.body.appendChild(node);
  }
  node.textContent = message;
  node.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('show'), 1800);
}

async function copy(text, label = 'Copied') {
  if (!text) return toast('Nothing to copy');
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Older browsers / insecure origins: fall back to a hidden textarea.
    const ta = el('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { return toast('Copy blocked by the browser'); }
    ta.remove();
  }
  toast(label);
}

/* ------------------------------------------------------------------- tabs */

const panels = [...document.querySelectorAll('.panel')];
const tabs = [...document.querySelectorAll('.tab')];

function showPanel(name) {
  panels.forEach((p) => p.classList.toggle('active', p.id === 'panel-' + name));
  tabs.forEach((t) => {
    const on = t.dataset.panel === name;
    t.classList.toggle('active', on);
    t.setAttribute('aria-selected', String(on));
  });
  document.body.dataset.panel = name;
  if (name === 'report') renderReport();
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}

tabs.forEach((t) => t.addEventListener('click', () => showPanel(t.dataset.panel)));

document.addEventListener('keydown', (e) => {
  if (e.target.matches('input, textarea, select')) return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const map = { 1: 'recon', 2: 'payload', 3: 'report', 4: 'toolset' };
  if (map[e.key]) showPanel(map[e.key]);
});

/* ------------------------------------------------------------- net status */

function paintNet() {
  const on = navigator.onLine;
  $('netStatus').classList.toggle('offline', !on);
  $('netLabel').textContent = on ? 'online' : 'offline';
}
addEventListener('online', paintNet);
addEventListener('offline', paintNet);
paintNet();
