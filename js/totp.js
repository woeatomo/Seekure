// Seekure — TOTP (RFC 6238) untuk 2FA, kompatibel dengan Google Authenticator,
// Microsoft Authenticator, Authy, Aegis, 2FAS, dll.

const subtle = globalThis.crypto.subtle;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const TOTP_PERIOD = 30;
export const TOTP_DIGITS = 6;

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Karakter base32 tidak valid.');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateSecret(byteLength = 20) {
  return base32Encode(globalThis.crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function hotp(secretBytes, counter, digits = TOTP_DIGITS) {
  const key = await subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    msg[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  const mac = new Uint8Array(await subtle.sign('HMAC', key, msg));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function counterAt(timeMs = Date.now(), period = TOTP_PERIOD) {
  return Math.floor(timeMs / 1000 / period);
}

export async function totp(secretB32, timeMs = Date.now(), { period = TOTP_PERIOD, digits = TOTP_DIGITS } = {}) {
  return hotp(base32Decode(secretB32), counterAt(timeMs, period), digits);
}

/**
 * Memverifikasi kode TOTP dengan toleransi ±window langkah (selisih jam).
 * Kode untuk counter <= lastCounter ditolak (anti-replay).
 * @returns counter yang cocok, atau null.
 */
export async function verifyTotp(secretB32, code, { timeMs = Date.now(), window = 1, lastCounter = -1 } = {}) {
  const clean = String(code).replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return null;
  const secret = base32Decode(secretB32);
  const now = counterAt(timeMs);
  let match = null;
  // Periksa semua kandidat (tanpa keluar lebih awal) agar waktu eksekusi seragam.
  for (let c = now - window; c <= now + window; c++) {
    const expected = await hotp(secret, c);
    let diff = 0;
    for (let i = 0; i < 6; i++) diff |= expected.charCodeAt(i) ^ clean.charCodeAt(i);
    if (diff === 0 && c > lastCounter && match === null) match = c;
  }
  return match;
}

export function otpauthUri(secretB32, { issuer = 'Seekure', account = 'Vault' } = {}) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret: secretB32, issuer, algorithm: 'SHA1', digits: String(TOTP_DIGITS), period: String(TOTP_PERIOD) });
  return `otpauth://totp/${label}?${params}`;
}
