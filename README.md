# Apex-Sec

A standalone, offline-capable security console. Charcoal and terminal green, no
framework, no build step, no server. Four modules in one installable PWA.

```
index.html            shell and markup
styles.css            charcoal / green / cyan theme
core.js               helpers, tab routing, network state (loaded first)
app.js                module logic: recon, encoders, hashes, report, toolset
manifest.webmanifest  PWA manifest
sw.js                 offline service worker
icons/                generated PNG icons (any + maskable)
```

Deploy is a static file copy — there is nothing to compile.

## Modules

**Apex Recon** — target intake, reachability probe, and a response-header audit
that checks HSTS, CSP, nosniff, frame options, Referrer-Policy and
Permissions-Policy, flags `unsafe-inline`/`unsafe-eval` CSPs, wildcard CORS and
`server` / `x-powered-by` disclosure. It also turns your port list into a ready
nmap command.

**Apex Payload & Encoder** — Base64 (standard and URL-safe), URL encode/decode,
hex, reverse, MD5/SHA-1/SHA-256/SHA-384/SHA-512, and a set of classic test
strings. Everything is computed in the tab; nothing is uploaded.

**Apex Bug Bounty Reporter** — title, asset, endpoint, request headers, steps,
impact and remediation become a triager-ready markdown report with copy and
`.md` download. Drafts survive a refresh (localStorage).

**Toolset Directory** — Nmap, Burp Suite, Metasploit, Wireshark, SQLmap and your
own scripts, each with a copyable command and a link to its documentation.

## What a browser cannot do (and why this app says so)

A web page cannot open raw TCP sockets, so **no browser-based tool can port
scan**. Anything that appears to is returning invented results. Apex-Sec does
the two things that are real:

- It probes with `fetch` and reports what that proves. A CORS-readable response
  gives the status, the real headers and a timing. An opaque response still
  proves DNS, TCP and TLS worked, because the request had to complete to return
  even an opaque result.
- It hands you the exact `nmap` and `curl` command for the ports you listed, so
  the real scan happens somewhere that can actually open sockets.

Header inspection is honest in the same way: if the target does not send
`Access-Control-Allow-Origin`, the browser hides the headers and the UI explains
that instead of guessing. Paste a raw header block from `curl -sSI` and the full
audit runs on it.

## Use

Open the URL, or install it (Chrome/Edge: the Install button; iOS: Share → Add to
Home Screen). Once installed it opens with no network at all — the encoders,
hashes and report generator are entirely local.

## Scope

Built for authorised testing: your own systems, or targets inside a programme
that permits it. The payload strings are standard test vectors, not weapons, and
sending them anywhere you do not own is a criminal offence in most countries.
