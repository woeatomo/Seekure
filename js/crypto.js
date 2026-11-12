// Seekure — lapisan kriptografi.
// Semua operasi memakai Web Crypto API bawaan browser (tanpa library pihak ketiga).
//
// Format brankas v2:
//
//   master password ──PBKDF2-SHA-256 (600k)──► KEK-pw ──membuka──► PK (32 byte acak)
//   kunci fisik (WebAuthn PRF) ──HKDF──────► KEK-hw ──membuka──► HK (32 byte acak)
//   kunci pemulihan (cetak)    ──HKDF──────► KEK-rk ──membuka──► HK
//
//   kunci data (DEK) = HKDF-SHA-256(PK ‖ HK)   → AES-256-GCM untuk seluruh isi brankas
//
// Tanpa kunci fisik, DEK = HKDF(PK). Dengan kunci fisik aktif, isi brankas hanya bisa
// didekripsi dengan password + (kunci fisik ATAU kunci pemulihan), bahkan bila file
// brankas dicuri dan password bocor.

import { base32Encode, base32Decode } from './totp.js';

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const VAULT_VERSION = 2;
export const PBKDF2_ITERATIONS = 600_000;

// ---------- util ----------
export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
export function toB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export async function sha256Hex(input) {
  const data = typeof input === 'string' ? enc.encode(input) : input;
  return toHex(new Uint8Array(await subtle.digest('SHA-256', data)));
}
/** Perbandingan string dengan waktu konstan (menghindari timing attack). */
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let diff = a.length ^ b.length;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

// ---------- penurunan kunci ----------
export async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
}

async function hkdfKey(ikm, salt, info) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function dataKey(pk, hk) {
  return hkdfKey(hk ? concat(pk, hk) : pk, enc.encode('seekure-dek-v2'), hk ? 'dek:password+hardware' : 'dek:password');
}

async function wrap(kek, secret, aad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, kek, secret);
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}
async function unwrap(kek, box, aad) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv), additionalData: enc.encode(aad) }, kek, fromB64(box.ct));
  return new Uint8Array(pt);
}

function kdfAad(kdf) {
  return JSON.stringify({ name: kdf.name, hash: kdf.hash, iterations: kdf.iterations, salt: kdf.salt });
}
function headerAad(v, kdf) {
  return enc.encode(JSON.stringify({ v, kdf: JSON.parse(kdfAad(kdf)) }));
}

async function passwordHeader(password, pk, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(16);
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toB64(salt) };
  const kek = await deriveKey(password, salt, iterations);
  return { kdf, pw: await wrap(kek, pk, 'seekure-pw|' + kdfAad(kdf)) };
}

function validateRecord(record) {
  if (!record || ![1, 2].includes(record.v) || !record.kdf || !record.iv || !record.ct) {
    throw new Error('Format vault tidak dikenali.');
  }
  const { name, hash, iterations, salt } = record.kdf;
  if (name !== 'PBKDF2' || hash !== 'SHA-256' || !Number.isInteger(iterations) || iterations < 100_000 || !salt) {
    throw new Error('Parameter KDF vault tidak valid.');
  }
  if (record.v === 2 && (!record.pw?.iv || !record.pw?.ct)) throw new Error('Format vault tidak dikenali.');
}

export function isValidRecord(record) {
  try { validateRecord(record); return true; } catch { return false; }
}

// ---------- siklus hidup brankas ----------
// "sess" adalah state rahasia yang hanya ada di memori selama brankas terbuka:
// { pk, hk, kdf, pw, hw }

/** Mengenkripsi data brankas dengan kunci dari sess (IV baru setiap kali). */
export async function sealVault(sess, data) {
  const key = await dataKey(sess.pk, sess.hk);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: headerAad(VAULT_VERSION, sess.kdf) },
    key,
    enc.encode(JSON.stringify(data)),
  );
  return { v: VAULT_VERSION, kdf: sess.kdf, pw: sess.pw, hw: sess.hw ?? null, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

export async function createVault(password, data, iterations = PBKDF2_ITERATIONS) {
  const pk = randomBytes(32);
  const sess = { pk, hk: null, hw: null, ...(await passwordHeader(password, pk, iterations)) };
  return { record: await sealVault(sess, data), sess };
}

async function openData(record, sess) {
  try {
    const key = await dataKey(sess.pk, sess.hk);
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(record.iv), additionalData: headerAad(record.v, record.kdf) },
      key,
      fromB64(record.ct),
    );
    return JSON.parse(dec.decode(pt));
  } catch {
    throw new Error('Vault rusak atau telah dimanipulasi.');
  }
}

/**
 * Langkah 1 membuka brankas: memeriksa master password.
 * @returns {{sess, data?, needsHardware?: boolean, migrated?: boolean}}
 */
export async function unlockPassword(record, password) {
  validateRecord(record);
  const kek = await deriveKey(password, fromB64(record.kdf.salt), record.kdf.iterations);

  if (record.v === 1) {
    // Format lama: data langsung dienkripsi dengan kunci dari password → migrasi ke v2.
    let pt;
    try {
      pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(record.iv), additionalData: headerAad(1, record.kdf) }, kek, fromB64(record.ct));
    } catch {
      throw new Error('Password salah atau vault rusak.');
    }
    const pk = randomBytes(32);
    const sess = { pk, hk: null, hw: null, ...(await passwordHeader(password, pk, record.kdf.iterations)) };
    return { sess, data: JSON.parse(dec.decode(pt)), migrated: true };
  }

  let pk;
  try {
    pk = await unwrap(kek, record.pw, 'seekure-pw|' + kdfAad(record.kdf));
  } catch {
    throw new Error('Password salah atau vault rusak.');
  }
  const sess = { pk, hk: null, kdf: record.kdf, pw: record.pw, hw: record.hw ?? null };
  if (sess.hw) return { sess, needsHardware: true };
  return { sess, data: await openData(record, sess) };
}

/** Langkah 2 (mode kunci fisik): membuka dengan output PRF dari kunci fisik. */
export async function unlockHardware(record, sess, credentialId, prf) {
  const slot = sess.hw?.slots.find((s) => s.id === credentialId);
  if (!slot) throw new Error('Kunci fisik ini tidak terdaftar di brankas.');
  try {
    const kek = await hkdfKey(prf, fromB64(slot.salt), 'seekure-hw-kek');
    sess.hk = await unwrap(kek, slot, 'seekure-hw|' + slot.id);
  } catch {
    throw new Error('Kunci fisik tidak cocok.');
  }
  return openData(record, sess);
}

/** Langkah 2 alternatif: membuka dengan kunci pemulihan cetak. */
export async function unlockRecoveryKey(record, sess, code) {
  const rk = sess.hw?.recovery;
  if (!rk) throw new Error('Brankas tidak memakai kunci fisik.');
  try {
    const kek = await hkdfKey(parseRecoveryKey(code), fromB64(rk.salt), 'seekure-rk-kek');
    sess.hk = await unwrap(kek, rk, 'seekure-rk');
  } catch {
    throw new Error('Kunci pemulihan salah.');
  }
  return openData(record, sess);
}

export async function changePassword(sess, newPassword, iterations = PBKDF2_ITERATIONS) {
  Object.assign(sess, await passwordHeader(newPassword, sess.pk, iterations));
}

// ---------- kunci fisik ----------
async function makeSlot(hk, { id, salt, prf, label }) {
  const kek = await hkdfKey(prf, fromB64(salt), 'seekure-hw-kek');
  return { type: 'webauthn', id, salt, label, createdAt: new Date().toISOString(), ...(await wrap(kek, hk, 'seekure-hw|' + id)) };
}

async function makeRecoveryBox(hk) {
  const raw = randomBytes(20);
  const salt = randomBytes(16);
  const kek = await hkdfKey(raw, salt, 'seekure-rk-kek');
  return { code: formatRecoveryKey(raw), box: { salt: toB64(salt), ...(await wrap(kek, hk, 'seekure-rk')) } };
}

/** Mengaktifkan mode kunci fisik. Mengembalikan kunci pemulihan (tampilkan sekali). */
export async function enableHardware(sess, firstKey) {
  const hk = randomBytes(32);
  const { code, box } = await makeRecoveryBox(hk);
  sess.hk = hk;
  sess.hw = { slots: [await makeSlot(hk, firstKey)], recovery: box };
  return code;
}

export async function addHardwareKey(sess, key) {
  if (!sess.hw || !sess.hk) throw new Error('Mode kunci fisik belum aktif.');
  if (sess.hw.slots.some((s) => s.id === key.id)) throw new Error('Kunci ini sudah terdaftar.');
  sess.hw = { ...sess.hw, slots: [...sess.hw.slots, await makeSlot(sess.hk, key)] };
}

export function removeHardwareKey(sess, id) {
  if (!sess.hw) return;
  if (sess.hw.slots.length <= 1) throw new Error('Minimal harus ada satu kunci fisik. Nonaktifkan mode kunci fisik bila ingin menghapus semuanya.');
  sess.hw = { ...sess.hw, slots: sess.hw.slots.filter((s) => s.id !== id) };
}

export async function regenerateRecoveryKey(sess) {
  const { code, box } = await makeRecoveryBox(sess.hk);
  sess.hw = { ...sess.hw, recovery: box };
  return code;
}

export function disableHardware(sess) {
  sess.hk = null;
  sess.hw = null;
}

// Kunci pemulihan: 160-bit acak, base32, 8 kelompok × 4 karakter.
export function formatRecoveryKey(raw) {
  return base32Encode(raw).match(/.{4}/g).join('-');
}
export function parseRecoveryKey(code) {
  const clean = String(code).toUpperCase().replace(/0/g, 'O').replace(/1/g, 'I').replace(/8/g, 'B').replace(/[^A-Z2-7]/g, '');
  if (clean.length !== 32) throw new Error('Panjang kunci pemulihan salah.');
  return base32Decode(clean);
}

// ---------- kode pemulihan 2FA (mode TOTP) ----------
const RC_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // tanpa 0/O/1/I

export function normalizeRecoveryCode(code) {
  return String(code).toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = randomBytes(12);
    let s = '';
    for (const b of bytes) s += RC_ALPHABET[b & 31];
    codes.push(`${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`);
  }
  return codes;
}

export function hashRecoveryCode(code) {
  return sha256Hex('seekure-recovery:' + normalizeRecoveryCode(code));
}

/** Sidik jari pendek private key: SHA-256, 16 byte pertama, dikelompokkan. */
export async function fingerprint(secret) {
  const hex = await sha256Hex(secret.trim());
  return hex.slice(0, 32).toUpperCase().match(/.{4}/g).join(':');
}
