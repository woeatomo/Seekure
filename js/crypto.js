// Seekure — lapisan kriptografi.
// Semua operasi memakai Web Crypto API bawaan browser (tanpa library pihak ketiga).
//
//  * Kunci enkripsi diturunkan dari master password dengan PBKDF2-HMAC-SHA-256
//    (600.000 iterasi, salt acak 16 byte) — hash yang sengaja dibuat lambat
//    supaya brute-force password sangat mahal.
//  * Isi vault dienkripsi dengan AES-256-GCM (IV acak 12 byte setiap simpan).
//    Header (versi + parameter KDF) ikut diautentikasi sebagai AAD sehingga
//    tidak bisa diubah diam-diam.
//  * Setiap private key diberi sidik jari SHA-256, kode pemulihan disimpan
//    hanya dalam bentuk hash SHA-256.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const VAULT_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;

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

export async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: kunci tidak bisa dibaca keluar dari memori Web Crypto
    ['encrypt', 'decrypt'],
  );
}

function headerAad(record) {
  const { v, kdf } = record;
  return enc.encode(JSON.stringify({ v, kdf: { name: kdf.name, hash: kdf.hash, iterations: kdf.iterations, salt: kdf.salt } }));
}

function validateRecord(record) {
  if (!record || record.v !== VAULT_VERSION || !record.kdf || !record.iv || !record.ct) {
    throw new Error('Format vault tidak dikenali.');
  }
  const { name, hash, iterations, salt } = record.kdf;
  if (name !== 'PBKDF2' || hash !== 'SHA-256' || !Number.isInteger(iterations) || iterations < 100_000 || !salt) {
    throw new Error('Parameter KDF vault tidak valid.');
  }
}

/** Mengenkripsi ulang data vault dengan kunci yang sudah ada (IV baru). */
export async function sealVault(header, key, data) {
  const record = { v: VAULT_VERSION, kdf: header.kdf };
  const iv = randomBytes(12);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: headerAad(record) },
    key,
    enc.encode(JSON.stringify(data)),
  );
  return { ...record, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

/** Membuat vault baru (salt baru) dari password. */
export async function createVault(password, data, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(16);
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toB64(salt) };
  const key = await deriveKey(password, salt, iterations);
  const record = await sealVault({ kdf }, key, data);
  return { record, key };
}

/** Membuka vault. Melempar error bila password salah atau data dimanipulasi. */
export async function openVault(record, password) {
  validateRecord(record);
  const key = await deriveKey(password, fromB64(record.kdf.salt), record.kdf.iterations);
  let plain;
  try {
    plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(record.iv), additionalData: headerAad(record) },
      key,
      fromB64(record.ct),
    );
  } catch {
    throw new Error('Password salah atau vault rusak.');
  }
  return { key, data: JSON.parse(dec.decode(plain)) };
}

// ---- Kode pemulihan (cadangan 2FA) ----

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
