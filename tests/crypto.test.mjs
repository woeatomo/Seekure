import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, unlockPassword, unlockHardware, unlockRecoveryKey, sealVault, sha256Hex, fingerprint,
  timingSafeEqual, generateRecoveryCodes, hashRecoveryCode, toB64, fromB64, deriveKey, randomBytes,
  changePassword, enableHardware, addHardwareKey, removeHardwareKey, regenerateRecoveryKey, disableHardware,
  parseRecoveryKey, isValidRecord,
} from '../js/crypto.js';
import { base32Encode, base32Decode, hotp, totp, verifyTotp, otpauthUri, counterAt } from '../js/totp.js';

const ITER = 100_000; // lebih cepat untuk test
const PW = 'password-sangat-kuat';
const fakeKey = (label = 'YubiKey') => ({ id: toB64(randomBytes(16)).replace(/[+/=]/g, 'x'), salt: toB64(randomBytes(32)), prf: randomBytes(32), label });

async function open(record, pw = PW) {
  const r = await unlockPassword(record, pw);
  return r.data;
}

test('vault: enkripsi lalu buka kembali dengan password benar', async () => {
  const data = { keys: [{ label: 'ETH', secret: '0xabc' }] };
  const { record } = await createVault(PW, data, ITER);
  assert.equal(record.v, 2);
  assert.ok(!JSON.stringify(record).includes('0xabc'), 'plaintext tidak boleh bocor');
  assert.deepEqual(await open(record), data);
});

test('vault: password salah ditolak', async () => {
  const { record } = await createVault(PW, { a: 1 }, ITER);
  await assert.rejects(unlockPassword(record, 'salah-salah-salah'), /Password salah/);
});

test('vault: ciphertext / header yang dimanipulasi ditolak', async () => {
  const { record } = await createVault(PW, { a: 1 }, ITER);
  const ct = fromB64(record.ct); ct[0] ^= 1;
  await assert.rejects(unlockPassword({ ...record, ct: toB64(ct) }, PW), /rusak/);
  await assert.rejects(unlockPassword({ ...record, kdf: { ...record.kdf, iterations: ITER + 1 } }, PW));
  assert.ok(isValidRecord(record));
  assert.ok(!isValidRecord({ v: 9 }));
});

test('vault: seal ulang memakai IV baru', async () => {
  const { record, sess } = await createVault(PW, { a: 1 }, ITER);
  const r2 = await sealVault(sess, { a: 2 });
  assert.notEqual(r2.iv, record.iv);
  assert.deepEqual(await open(r2), { a: 2 });
});

test('vault: ganti password', async () => {
  const { sess } = await createVault(PW, { a: 1 }, ITER);
  await changePassword(sess, 'password-baru-yang-panjang', ITER);
  const r = await sealVault(sess, { a: 1 });
  await assert.rejects(unlockPassword(r, PW), /Password salah/);
  assert.deepEqual(await open(r, 'password-baru-yang-panjang'), { a: 1 });
});

test('vault: migrasi otomatis dari format v1', async () => {
  // Bangun record v1 secara manual (format rilis pertama).
  const salt = randomBytes(16);
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations: ITER, salt: toB64(salt) };
  const key = await deriveKey(PW, salt, ITER);
  const iv = randomBytes(12);
  const aad = new TextEncoder().encode(JSON.stringify({ v: 1, kdf }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, new TextEncoder().encode('{"x":42}'));
  const v1 = { v: 1, kdf, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
  const r = await unlockPassword(v1, PW);
  assert.ok(r.migrated);
  assert.deepEqual(r.data, { x: 42 });
  const v2 = await sealVault(r.sess, r.data);
  assert.equal(v2.v, 2);
  assert.deepEqual(await open(v2), { x: 42 });
});

test('kunci fisik: password saja TIDAK cukup untuk mendekripsi', async () => {
  const { sess } = await createVault(PW, { s: 'rahasia' }, ITER);
  const k1 = fakeKey();
  const rk = await enableHardware(sess, k1);
  const record = await sealVault(sess, { s: 'rahasia' });

  const step1 = await unlockPassword(record, PW);
  assert.equal(step1.needsHardware, true);
  assert.equal(step1.data, undefined);
  // Penyerang dengan file + password tanpa HK: mencoba DEK password-only gagal.
  await assert.rejects(unlockHardware(record, step1.sess, k1.id, randomBytes(32)), /tidak cocok/);
  await assert.rejects(unlockHardware(record, step1.sess, 'id-lain', k1.prf), /tidak terdaftar/);

  const s2 = (await unlockPassword(record, PW)).sess;
  assert.deepEqual(await unlockHardware(record, s2, k1.id, k1.prf), { s: 'rahasia' });

  const s3 = (await unlockPassword(record, PW)).sess;
  assert.deepEqual(await unlockRecoveryKey(record, s3, rk.toLowerCase()), { s: 'rahasia' });
  const s4 = (await unlockPassword(record, PW)).sess;
  await assert.rejects(unlockRecoveryKey(record, s4, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'), /salah/);

  // Password tetap wajib walau punya kunci fisik.
  await assert.rejects(unlockPassword(record, 'tebakan-password-salah'), /Password salah/);
});

test('kunci fisik: kunci cadangan, hapus kunci, kunci pemulihan baru, ganti password, nonaktifkan', async () => {
  const { sess } = await createVault(PW, { n: 1 }, ITER);
  const k1 = fakeKey('Utama'), k2 = fakeKey('Cadangan');
  const rkOld = await enableHardware(sess, k1);
  await addHardwareKey(sess, k2);
  await assert.rejects(addHardwareKey(sess, k2), /sudah terdaftar/);
  let record = await sealVault(sess, { n: 1 });
  assert.deepEqual(await unlockHardware(record, (await unlockPassword(record, PW)).sess, k2.id, k2.prf), { n: 1 });

  removeHardwareKey(sess, k1.id);
  assert.throws(() => removeHardwareKey(sess, k2.id), /Minimal/);
  const rkNew = await regenerateRecoveryKey(sess);
  await changePassword(sess, 'password-baru-yang-panjang', ITER);
  record = await sealVault(sess, { n: 2 });
  const fresh = async () => (await unlockPassword(record, 'password-baru-yang-panjang')).sess;
  await assert.rejects(unlockHardware(record, await fresh(), k1.id, k1.prf), /tidak terdaftar/);
  await assert.rejects(unlockRecoveryKey(record, await fresh(), rkOld), /salah/);
  assert.deepEqual(await unlockRecoveryKey(record, await fresh(), rkNew), { n: 2 });
  assert.deepEqual(await unlockHardware(record, await fresh(), k2.id, k2.prf), { n: 2 });

  disableHardware(sess);
  record = await sealVault(sess, { n: 3 });
  assert.equal(record.hw, null);
  assert.deepEqual(await open(record, 'password-baru-yang-panjang'), { n: 3 });
});

test('kunci pemulihan: format & toleran salah ketik 0/O 1/I', () => {
  const raw = randomBytes(20);
  const code = base32Encode(raw).match(/.{4}/g).join('-');
  assert.deepEqual(parseRecoveryKey(code.replace(/O/g, '0').replace(/I/g, '1').toLowerCase()), raw);
  assert.throws(() => parseRecoveryKey('ABCD'), /Panjang/);
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
