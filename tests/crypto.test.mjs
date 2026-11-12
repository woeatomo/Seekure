import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, openVault, sealVault, sha256Hex, fingerprint, timingSafeEqual,
  generateRecoveryCodes, hashRecoveryCode, toB64, fromB64,
} from '../js/crypto.js';
import { base32Encode, base32Decode, hotp, totp, verifyTotp, otpauthUri, counterAt } from '../js/totp.js';

const ITER = 100_000; // lebih cepat untuk test

test('vault: enkripsi lalu buka kembali dengan password benar', async () => {
  const data = { keys: [{ label: 'ETH', secret: '0xabc' }] };
  const { record } = await createVault('password-sangat-kuat', data, ITER);
  assert.ok(!JSON.stringify(record).includes('0xabc'), 'plaintext tidak boleh bocor');
  const { data: out } = await openVault(record, 'password-sangat-kuat');
  assert.deepEqual(out, data);
});

test('vault: password salah ditolak', async () => {
  const { record } = await createVault('benar-benar-benar', { a: 1 }, ITER);
  await assert.rejects(openVault(record, 'salah-salah-salah'), /Password salah/);
});

test('vault: ciphertext / header yang dimanipulasi ditolak', async () => {
  const { record } = await createVault('benar-benar-benar', { a: 1 }, ITER);
  const ct = fromB64(record.ct); ct[0] ^= 1;
  await assert.rejects(openVault({ ...record, ct: toB64(ct) }, 'benar-benar-benar'));
  await assert.rejects(openVault({ ...record, kdf: { ...record.kdf, iterations: ITER + 1 } }, 'benar-benar-benar'));
});

test('vault: seal ulang memakai IV baru', async () => {
  const { record, key } = await createVault('benar-benar-benar', { a: 1 }, ITER);
  const r2 = await sealVault(record, key, { a: 2 });
  assert.notEqual(r2.iv, record.iv);
  assert.deepEqual((await openVault(r2, 'benar-benar-benar')).data, { a: 2 });
});

test('hash SHA-256 & sidik jari', async () => {
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.match(await fingerprint('kunci'), /^([0-9A-F]{4}:){7}[0-9A-F]{4}$/);
  assert.ok(timingSafeEqual('abc', 'abc'));
  assert.ok(!timingSafeEqual('abc', 'abd'));
});

test('kode pemulihan: hash tidak peka format', async () => {
  const [code] = generateRecoveryCodes(1);
  assert.match(code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.equal(await hashRecoveryCode(code), await hashRecoveryCode(code.toLowerCase().replace(/-/g, ' ')));
});

test('base32 round-trip', () => {
  const bytes = new Uint8Array([1, 2, 3, 250, 99, 0, 7]);
  assert.deepEqual(base32Decode(base32Encode(bytes)), bytes);
  assert.equal(base32Encode(new TextEncoder().encode('12345678901234567890')), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});

test('TOTP: vektor uji RFC 6238 (SHA-1, 8 digit)', async () => {
  const secret = new TextEncoder().encode('12345678901234567890');
  const vectors = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [t, expected] of vectors) {
    assert.equal(await hotp(secret, Math.floor(t / 30), 8), expected, `t=${t}`);
  }
});

test('TOTP: verifikasi, toleransi waktu dan anti-replay', async () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  const t = 1_700_000_000_000;
  const code = await totp(secret, t);
  const c = counterAt(t);
  assert.equal(await verifyTotp(secret, code, { timeMs: t }), c);
  assert.equal(await verifyTotp(secret, code, { timeMs: t + 30_000 }), c); // jam sedikit beda
  assert.equal(await verifyTotp(secret, code, { timeMs: t + 120_000 }), null); // kedaluwarsa
  assert.equal(await verifyTotp(secret, code, { timeMs: t, lastCounter: c }), null); // replay
  assert.equal(await verifyTotp(secret, '12345', { timeMs: t }), null);
  assert.match(otpauthUri(secret), /^otpauth:\/\/totp\/Seekure%3AVault\?secret=JBSWY3DPEHPK3PXP&issuer=Seekure/);
});
