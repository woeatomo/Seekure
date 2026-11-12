// Service worker: menyimpan file aplikasi agar Seekure bisa dipakai sepenuhnya offline.
// Data vault TIDAK pernah dikirim ke jaringan.
const CACHE = 'seekure-v4';
const ASSETS = [
  './', 'index.html', 'css/style.css', 'js/app.js', 'js/crypto.js', 'js/totp.js', 'js/webauthn.js', 'js/version.js',
  'vendor/qrcode.js', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request)));
});
