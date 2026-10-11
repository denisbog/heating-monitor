/* Service worker for the heating monitor.
 *
 * Strategy:
 *   - precache the app shell, so the page opens instantly and works offline
 *   - navigations are network-first, so a deploy is picked up as soon as you're online
 *   - other static assets are stale-while-revalidate
 *   - /api/* is NEVER cached: it is live sensor data, and showing a stale reading
 *     as if it were current would be worse than showing an error
 *
 * Bump VERSION only if the precache list itself changes.
 */
const VERSION = "v1";
const SHELL = `${VERSION}-shell`;
const PRECACHE = [
  "/",
  "/index.html",
  "/manifest.webmanifest",
  "/icon-192.png",
  "/icon-512.png",
  "/icon-maskable-512.png",
  "/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(SHELL);
      await cache.addAll(PRECACHE);
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // Live data and the mutable endpoints always go to the network.
  if (url.pathname.startsWith("/api/")) return;

  if (req.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req);
          const cache = await caches.open(SHELL);
          await cache.put("/index.html", res.clone());
          return res;
        } catch {
          return (await caches.match("/index.html")) || Response.error();
        }
      })(),
    );
    return;
  }

  event.respondWith(
    (async () => {
      const cached = await caches.match(req);
      const fromNetwork = fetch(req)
        .then((res) => {
          if (res && res.ok) {
            caches.open(SHELL).then((c) => c.put(req, res.clone()));
          }
          return res;
        })
        .catch(() => null);
      return cached || (await fromNetwork) || Response.error();
    })(),
  );
});
