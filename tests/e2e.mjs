// Uji end-to-end di Chromium (Playwright).
// Jalankan: node tests/e2e.mjs [folder-screenshot]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { totp } from '../js/totp.js';

const { chromium, devices } = createRequire(import.meta.url)('playwright');
const root = fileURLToPath(new URL('..', import.meta.url));
const shotDir = process.argv[2];
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };

const server = createServer(async (req, res) => {
  const file = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^([/\\])+/, '') || 'index.html';
  try {
    const body = await readFile(join(root, file));
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(body);
  } catch { res.writeHead(404).end(); }
}).listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
// "localhost" (bukan IP) karena WebAuthn butuh nama domain sebagai RP ID.
const url = process.env.BASE_URL || `http://localhost:${server.address().port}/`;

const PW = 'kuda-terbang-makan-nasi-goreng-42';
const KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const visible = (id) => `#${id}:not([hidden])`;

async function newPage(browser, contextOpts) {
  const ctx = await browser.newContext({ ...contextOpts, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  const t = { now: Date.UTC(2026, 10, 12, 8, 0, 5) };
  await page.clock.install({ time: t.now });
  t.advance = async (ms = 30_000) => { t.now += ms; await page.clock.setSystemTime(t.now); };
  return { ctx, page, errors, t };
}

async function setupVault(page, t, snap = async () => {}) {
  await page.goto(url);
  await page.fill('#setup-pw', PW);
  await page.fill('#setup-pw2', PW);
  await snap('1-setup');
  await page.click('#form-setup button[type=submit]');
  const secret = (await page.textContent('#totp-secret-text')).replace(/\s/g, '');
  assert.match(secret, /^[A-Z2-7]{32}$/);
  await page.fill('#setup-otp', '000000');
  await page.click('#form-2fa-setup button[type=submit]');
  assert.match(await page.textContent('#twofa-error'), /salah/);
  await snap('2-2fa');
  await page.fill('#setup-otp', await totp(secret, t.now));
  await page.click('#form-2fa-setup button[type=submit]');
  await page.waitForSelector(visible('screen-recovery'));
  const codes = await page.$$eval('#recovery-list li', (li) => li.map((x) => x.textContent));
  assert.equal(codes.length, 8);
  await snap('3-recovery');
  await page.click('#btn-recovery-done');

  await page.click('#btn-add');
  await page.fill('#key-label', 'Wallet ETH utama');
  await page.fill('#key-secret', KEY);
  await page.fill('#key-notes', 'Hot wallet harian');
  await page.click('#form-key button[type=submit]');
  await page.waitForSelector('.key');
  return { secret, codes };
}

async function enterPassword(page, pw = PW) {
  await page.fill('#unlock-pw', pw);
  await page.click('#btn-unlock');
}

async function unlockTotp(page, t, secret) {
  await enterPassword(page);
  await page.waitForSelector(visible('screen-verify'));
  await t.advance();
  await page.fill('#verify-otp', await totp(secret, t.now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForSelector(`${visible('screen-vault')} .key`);
}

/** Mode "tahan untuk lihat": key hanya terlihat selama tombol ditekan. */
async function readSecretHeld(page) {
  await page.locator('.key .hold-btn').first().hover();
  await page.mouse.down();
  const text = await page.textContent('.secret-box');
  assert.ok(await page.isVisible('.secret-box'));
  return {
    text,
    release: async () => {
      await page.mouse.up();
      assert.ok(await page.isHidden('.secret-box'), 'key harus tersembunyi setelah tombol dilepas');
    },
  };
}

function assertEncrypted(stored) {
  assert.ok(!stored.includes(KEY.slice(2, 20)) && !stored.includes('Wallet'), 'vault harus terenkripsi');
}

// ---------------------------------------------------------------------------
async function runTotp(name, contextOpts) {
  const browser = await chromium.launch();
  const { page, errors, t } = await newPage(browser, contextOpts);
  const snap = async (label) => shotDir && page.screenshot({ path: `${shotDir}/${name}-${label}.png`, fullPage: true });

  const { secret, codes } = await setupVault(page, t, snap);
  const held = await readSecretHeld(page);
  assert.equal(held.text, KEY);
  await snap('4-vault');
  await held.release();

  // Layar disamarkan saat aplikasi tidak aktif; key yang tampil ikut disembunyikan
  await page.locator('.key .hold-btn').hover();
  await page.mouse.down();
  await page.evaluate(() => dispatchEvent(new Event('blur')));
  assert.ok(await page.evaluate(() => document.body.classList.contains('privacy')));
  assert.ok(await page.isHidden('.secret-box'));
  await snap('4b-privacy');
  await page.mouse.up();
  await page.evaluate(() => dispatchEvent(new Event('focus')));
  assert.ok(!(await page.evaluate(() => document.body.classList.contains('privacy'))));

  // Mode klik-untuk-tampil (opsional) + nonaktifkan penyamaran
  await page.click('#btn-settings');
  assert.match(await page.textContent('#app-version'), /^Seekure v\d+\.\d+\.\d+ · versi offline/);
  await page.evaluate(() => { document.querySelector('#reveal-mode').closest('details').open = true; });
  await page.selectOption('#reveal-mode', 'toggle');
  await page.uncheck('#privacy-blur');
  await page.click('#btn-settings-close');
  await page.click('.key button:has-text("Tampilkan")');
  assert.equal(await page.textContent('.secret-box'), KEY);
  await page.evaluate(() => dispatchEvent(new Event('blur')));
  assert.ok(!(await page.evaluate(() => document.body.classList.contains('privacy'))));
  assert.ok(await page.isHidden('.secret-box'), 'key tetap disembunyikan saat jendela tidak aktif');
  await page.evaluate(() => dispatchEvent(new Event('focus')));
  await page.click('#btn-settings');
  await page.selectOption('#reveal-mode', 'hold');
  await page.check('#privacy-blur');
  await page.click('#btn-settings-close');
  assertEncrypted(await page.evaluate(() => localStorage.getItem('seekure.vault')));

  // kunci → password salah → benar → kode lama (replay) ditolak → kode baru
  await page.click('#btn-lock');
  await enterPassword(page, 'password-salah-sekali');
  await page.waitForFunction(() => document.getElementById('unlock-error').textContent.length > 0);
  await enterPassword(page);
  await page.waitForSelector(visible('screen-verify'));
  await page.fill('#verify-otp', await totp(secret, t.now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForFunction(() => /sudah dipakai/.test(document.getElementById('verify-error').textContent));
  await snap('5-verify');
  await t.advance();
  await page.fill('#verify-otp', await totp(secret, t.now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForSelector(`${visible('screen-vault')} .key`);

  // kode pemulihan sekali pakai
  await page.click('#btn-lock');
  for (const attempt of [1, 2]) {
    await enterPassword(page);
    await page.waitForSelector(visible('screen-verify'));
    await page.click('#btn-toggle-recovery');
    await page.fill('#verify-otp', codes[0].toLowerCase());
    await page.click('#form-verify button[type=submit]');
    if (attempt === 1) {
      await page.waitForSelector(visible('screen-vault'));
      await page.click('#btn-lock');
    } else {
      await page.waitForFunction(() => /tidak valid/.test(document.getElementById('verify-error').textContent));
      await page.click('#btn-verify-cancel');
    }
  }

  // auto-lock
  await unlockTotp(page, t, secret);
  await page.click('#btn-settings');
  await snap('6-settings');
  await page.click('#btn-settings-close');
  await page.clock.runFor(5 * 60_000 + 1000);
  await page.waitForSelector(visible('screen-unlock'));

  assert.deepEqual(errors, []);
  await browser.close();
  console.log(`✔ ${name}`);
}

// ---------------------------------------------------------------------------
async function runHardware(name, contextOpts) {
  const browser = await chromium.launch();
  const { page, errors, t } = await newPage(browser, contextOpts);
  const snap = async (label) => shotDir && page.screenshot({ path: `${shotDir}/${name}-${label}.png`, fullPage: true });
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const addKey = async () => (await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true },
  })).authenticatorId;

  const { secret } = await setupVault(page, t);
  const keyA = await addKey();

  // Aktifkan kunci fisik: password salah ditolak
  await page.click('#btn-settings');
  await page.evaluate(() => { document.getElementById('hw-details').open = true; });
  await snap('1-settings-hw');
  await page.fill('#hw-enable-pw', 'bukan-password-saya');
  await page.click('#form-hw-enable button[type=submit]');
  await page.waitForFunction(() => /salah/.test(document.getElementById('hw-enable-error').textContent));
  await page.fill('#hw-enable-pw', PW);
  await page.click('#form-hw-enable button[type=submit]');
  await page.waitForSelector(visible('screen-rk-show'));
  const rk = await page.textContent('#rk-show');
  assert.match(rk, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
  await snap('2-recovery-key');
  await page.fill('#rk-confirm', 'ZZZZ');
  await page.click('#btn-rk-done');
  assert.match(await page.textContent('#rk-show-error'), /tidak cocok/);
  await page.fill('#rk-confirm', rk.slice(-4).toLowerCase());
  await page.click('#btn-rk-done');
  await page.waitForSelector(visible('screen-settings'));
  assert.equal(await page.textContent('#hw-status'), 'Aktif');
  assert.ok(await page.isHidden('#totp-reset-details'));

  // Kunci cadangan (kunci B); kunci A "dicabut" dulu supaya hanya B yang merespons
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: keyA, enabled: false });
  const keyB = await addKey();
  await page.evaluate(() => { document.getElementById('hw-details').open = true; });
  await page.click('#form-hw-add button[type=submit]');
  await page.waitForFunction(() => document.querySelectorAll('#hw-list li').length === 2);
  await snap('3-two-keys');

  const stored = await page.evaluate(() => localStorage.getItem('seekure.vault'));
  assertEncrypted(stored);
  assert.equal(JSON.parse(stored).hw.slots.length, 2);

  // Kunci → password salah tetap ditolak → password benar → layar kunci fisik
  await page.click('#btn-lock');
  await enterPassword(page, 'password-salah-sekali');
  await page.waitForFunction(() => document.getElementById('unlock-error').textContent.length > 0);
  await enterPassword(page);
  await page.waitForSelector(visible('screen-hw'));
  await snap('4-touch-key');
  await page.click('#btn-hw-unlock'); // hanya kunci B yang aktif
  await page.waitForSelector(`${visible('screen-vault')} .key`);

  // Kunci A hilang → hapus dari brankas; buka dengan kunci pemulihan
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: keyA });
  page.once('dialog', (d) => d.accept());
  await page.click('#btn-settings');
  await page.evaluate(() => { document.getElementById('hw-details').open = true; });
  await page.click('#hw-list li:first-child button');
  await page.waitForFunction(() => document.querySelectorAll('#hw-list li').length === 1);
  assert.ok(await page.isDisabled('#hw-list li button'), 'kunci terakhir tidak boleh dihapus');

  await page.click('#btn-lock');
  await enterPassword(page);
  await page.waitForSelector(visible('screen-hw'));
  await page.click('#btn-toggle-rk');
  await page.fill('#rk-input', 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA');
  await page.click('#form-rk button[type=submit]');
  await page.waitForFunction(() => /salah/.test(document.getElementById('hw-error').textContent));
  await page.fill('#rk-input', rk.toLowerCase().replace(/-/g, ' '));
  await page.click('#form-rk button[type=submit]');
  await page.waitForSelector(`${visible('screen-vault')} .key`);
  const held = await readSecretHeld(page);
  assert.equal(held.text, KEY);
  await held.release();

  // Kunci B dicabut → kunci fisik tidak bisa → pesan error ramah (timeout disingkat)
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: keyB, enabled: false });
  await page.click('#btn-lock');
  await enterPassword(page);
  await page.waitForSelector(visible('screen-hw'));
  await page.evaluate(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (o) => get({ ...o, publicKey: { ...o.publicKey, timeout: 1500 } });
  });
  await page.click('#btn-hw-unlock');
  await page.waitForFunction(() => /Dibatalkan atau waktu habis/.test(document.getElementById('hw-error').textContent), null, { timeout: 15_000 });
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: keyB, enabled: true });
  await page.click('#btn-hw-unlock');
  await page.waitForSelector(visible('screen-vault'));

  // Nonaktifkan kunci fisik → wajib QR TOTP baru → kembali ke password + TOTP
  await page.click('#btn-settings');
  await page.evaluate(() => { document.getElementById('hw-details').open = true; });
  await page.fill('#hw-disable-pw', PW);
  await page.click('#form-hw-disable button[type=submit]');
  await page.waitForSelector(visible('screen-2fa-setup'));
  const secret2 = (await page.textContent('#totp-secret-text')).replace(/\s/g, '');
  assert.notEqual(secret2, secret);
  await page.fill('#setup-otp', await totp(secret2, t.now));
  await page.click('#form-2fa-setup button[type=submit]');
  await page.waitForSelector(visible('screen-settings'));
  assert.equal(await page.textContent('#hw-status'), 'Nonaktif');
  assert.equal(JSON.parse(await page.evaluate(() => localStorage.getItem('seekure.vault'))).hw, null);
  await page.click('#btn-lock');
  await unlockTotp(page, t, secret2);

  assert.deepEqual(errors.filter((e) => !/NotAllowedError|timed out/.test(e)), []);
  await browser.close();
  console.log(`✔ ${name}`);
}

try {
  await runTotp('desktop', { viewport: { width: 1280, height: 860 } });
  await runTotp('mobile', { ...devices['Pixel 7'] });
  await runHardware('hwkey-desktop', { viewport: { width: 1280, height: 860 } });
  await runHardware('hwkey-mobile', { ...devices['Pixel 7'] });
} finally {
  server.close();
}
