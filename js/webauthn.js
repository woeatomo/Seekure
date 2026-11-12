// Seekure — kunci fisik (YubiKey, SoloKey, Google Titan, Feitian, dll.) via WebAuthn PRF.
//
// Ekstensi PRF (berbasis CTAP2 "hmac-secret") membuat kunci fisik menghitung
// HMAC dari salt yang kita berikan memakai rahasia yang tidak pernah keluar dari
// chip-nya. Hasil 32 byte itu dipakai sebagai bahan kunci enkripsi brankas.
//
// PIN kunci (user verification) selalu diwajibkan: hmac-secret menghasilkan nilai
// BERBEDA dengan dan tanpa PIN, jadi mode harus konsisten setiap kali dipakai.
// Bonus: kunci fisik yang dicuri tidak bisa dipakai tanpa PIN-nya.

import { randomBytes, toB64, fromB64 } from './crypto.js';

const TIMEOUT = 120_000;

export function toB64url(bytes) {
  return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64url(s) {
  return fromB64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
}

export function hardwareSupported() {
  return Boolean(globalThis.PublicKeyCredential && globalThis.isSecureContext && navigator.credentials);
}

const UNSUPPORTED = 'Kunci fisik atau browser ini tidak mendukung ekstensi PRF (hmac-secret). Gunakan YubiKey 5 / kunci FIDO2 lain di Chrome atau Edge versi terbaru.';

function friendly(err) {
  switch (err?.name) {
    case 'NotAllowedError': return new Error('Dibatalkan atau waktu habis. Coba lagi lalu sentuh kunci fisik Anda.');
    case 'InvalidStateError': return new Error('Kunci fisik ini sudah terdaftar di brankas.');
    case 'SecurityError': return new Error('Kunci fisik butuh HTTPS dan domain yang valid.');
    case 'NotSupportedError': return new Error(UNSUPPORTED);
    default: return err instanceof Error ? err : new Error(String(err));
  }
}

/**
 * Mendaftarkan kunci fisik baru.
 * @returns {{id: string, salt: string, prf: Uint8Array, label: string}}
 */
export async function registerKey(label, existingIds = []) {
  const salt = randomBytes(32);
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'Seekure', id: location.hostname },
        user: { id: randomBytes(16), name: 'seekure-vault', displayName: `Seekure — ${label}` },
        challenge: randomBytes(32),
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },   // ES256
          { type: 'public-key', alg: -8 },   // EdDSA
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
        excludeCredentials: existingIds.map((id) => ({ type: 'public-key', id: fromB64url(id) })),
        hints: ['security-key'],
        attestation: 'none',
        timeout: TIMEOUT,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw friendly(e);
  }
  const id = toB64url(new Uint8Array(cred.rawId));
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error(UNSUPPORTED);

  const slot = { id, salt: toB64(salt), label };
  if (ext.results?.first) return { ...slot, prf: new Uint8Array(ext.results.first) };
  // Sebagian kunci baru mengeluarkan hasil PRF saat autentikasi → minta sentuhan kedua.
  const { prf } = await evaluateKey([slot]);
  return { ...slot, prf };
}

/**
 * Meminta salah satu kunci fisik terdaftar menghitung PRF.
 * @returns {{id: string, prf: Uint8Array}}
 */
export async function evaluateKey(slots) {
  let res;
  try {
    res = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: location.hostname,
        allowCredentials: slots.map((s) => ({ type: 'public-key', id: fromB64url(s.id) })),
        userVerification: 'required',
        hints: ['security-key'],
        timeout: TIMEOUT,
        extensions: { prf: { evalByCredential: Object.fromEntries(slots.map((s) => [s.id, { first: fromB64(s.salt) }])) } },
      },
    });
  } catch (e) {
    throw friendly(e);
  }
  const first = res.getClientExtensionResults().prf?.results?.first;
  if (!first) throw new Error(UNSUPPORTED);
  return { id: toB64url(new Uint8Array(res.rawId)), prf: new Uint8Array(first) };
}
