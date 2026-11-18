/* Apex-Sec service worker.
   Precache the shell so the console opens with no network at all — the encoder,
   hashes and report generator are entirely local, so offline is a real state and
   not a degraded one. The recon probe obviously needs a network and says so. */

const CACHE = 'apex-sec-v2';

const SHELL = [
  './',
  'index.html',
  'styles.css',
  'core.js',
  'app.js',
  'manifest.webmanifest',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/maskable-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // addAll fails the whole install if any single file 404s, so add alone.
      await Promise.all(SHELL.map((url) => cache.add(url).catch(() => {})));
      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;

  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // Never cache another origin. The recon probe is a live request by definition,
  // and caching it would quietly answer with a stale result.
  if (url.origin !== self.location.origin) return;

  // Navigations: network first so a deploy is picked up, cache as the fallback.
  if (request.mode === 'navigate') {
    event.respondWith(
      (async () => {
        try {
          const fresh = await fetch(request);
          const cache = await caches.open(CACHE);
          cache.put('index.html', fresh.clone());
          return fresh;
        } catch {
          const cache = await caches.open(CACHE);
          return (await cache.match('index.html')) || (await cache.match('./')) ||
            new Response('Apex-Sec is offline and the shell is not cached yet.', {
              status: 503,
              headers: { 'Content-Type': 'text/plain' },
            });
        }
      })()
    );
    return;
  }

  // Everything else: cache first, refresh in the background.
  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(request);
      if (hit) {
        fetch(request)
          .then((res) => { if (res && res.ok) cache.put(request, res.clone()); })
          .catch(() => {});
        return hit;
      }
      try {
        const res = await fetch(request);
        if (res && res.ok) cache.put(request, res.clone());
        return res;
      } catch {
        return new Response('Offline', { status: 503 });
      }
    })()
  );
});
