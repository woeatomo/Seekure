// Uji end-to-end di Chromium (Playwright): setup → 2FA → tambah key → kunci → buka.
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
const url = `http://127.0.0.1:${server.address().port}/`;

const PW = 'kuda-terbang-makan-nasi-goreng-42';
const KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

async function run(name, contextOpts) {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ...contextOpts, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  let now = Date.UTC(2026, 10, 12, 8, 0, 5);
  await page.clock.install({ time: now });
  const snap = async (label) => shotDir && page.screenshot({ path: `${shotDir}/${name}-${label}.png`, fullPage: true });

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
  await page.fill('#setup-otp', await totp(secret, now));
  await page.click('#form-2fa-setup button[type=submit]');

  await page.waitForSelector('#screen-recovery:not([hidden])');
  const codes = await page.$$eval('#recovery-list li', (li) => li.map((x) => x.textContent));
  assert.equal(codes.length, 8);
  await snap('3-recovery');
  await page.click('#btn-recovery-done');

  // tambah key
  await page.click('#btn-add');
  await page.fill('#key-label', 'Wallet ETH utama');
  await page.fill('#key-secret', KEY);
  await page.fill('#key-notes', 'Hot wallet harian');
  await page.click('#form-key button[type=submit]');
  await page.waitForSelector('.key');
  await page.click('.key button:has-text("Tampilkan")');
  assert.equal(await page.textContent('.secret-box'), KEY);
  await snap('4-vault');

  // tidak ada plaintext di storage
  const stored = await page.evaluate(() => localStorage.getItem('seekure.vault'));
  assert.ok(!stored.includes(KEY.slice(2, 20)) && !stored.includes('Wallet'), 'vault harus terenkripsi');

  // kunci → password salah → password benar → kode lama (replay) ditolak → kode baru
  await page.click('#btn-lock');
  await page.fill('#unlock-pw', 'password-salah-sekali');
  await page.click('#btn-unlock');
  await page.waitForFunction(() => document.getElementById('unlock-error').textContent.length > 0);
  await page.fill('#unlock-pw', PW);
  await page.click('#btn-unlock');
  await page.waitForSelector('#screen-verify:not([hidden])');
  await page.fill('#verify-otp', await totp(secret, now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForFunction(() => /sudah dipakai/.test(document.getElementById('verify-error').textContent));
  await snap('5-verify');
  now += 30_000;
  await page.clock.setSystemTime(now);
  await page.fill('#verify-otp', await totp(secret, now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForSelector('#screen-vault:not([hidden]) .key');

  // buka dengan kode pemulihan (sekali pakai)
  await page.click('#btn-lock');
  for (const attempt of [1, 2]) {
    await page.fill('#unlock-pw', PW);
    await page.click('#btn-unlock');
    await page.waitForSelector('#screen-verify:not([hidden])');
    await page.click('#btn-toggle-recovery');
    await page.fill('#verify-otp', codes[0].toLowerCase());
    await page.click('#form-verify button[type=submit]');
    if (attempt === 1) {
      await page.waitForSelector('#screen-vault:not([hidden])');
      await page.click('#btn-lock');
    } else {
      await page.waitForFunction(() => /tidak valid/.test(document.getElementById('verify-error').textContent));
      await page.click('#btn-verify-cancel');
    }
  }

  // auto-lock karena tidak aktif
  await page.fill('#unlock-pw', PW);
  await page.click('#btn-unlock');
  await page.waitForSelector('#screen-verify:not([hidden])');
  now += 30_000;
  await page.clock.setSystemTime(now);
  await page.fill('#verify-otp', await totp(secret, now));
  await page.click('#form-verify button[type=submit]');
  await page.waitForSelector('#screen-vault:not([hidden])');
  await page.click('#btn-settings');
  await snap('6-settings');
  await page.click('#btn-settings-close');
  await page.clock.runFor(5 * 60_000 + 1000);
  await page.waitForSelector('#screen-unlock:not([hidden])');

  assert.deepEqual(errors, []);
  await browser.close();
  console.log(`✔ ${name}`);
}

try {
  await run('desktop', { viewport: { width: 1280, height: 860 } });
  await run('mobile', { ...devices['Pixel 7'] });
} finally {
  server.close();
}
