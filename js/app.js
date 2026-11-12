import {
  createVault, openVault, sealVault, randomBytes, toB64,
  generateRecoveryCodes, hashRecoveryCode, timingSafeEqual, fingerprint, PBKDF2_ITERATIONS,
} from './crypto.js';
import { generateSecret, verifyTotp, otpauthUri } from './totp.js';

const STORE_KEY = 'seekure.vault';
const LOCK_KEY = 'seekure.lockout';
const MAX_FREE_FAILS = 5;
const CLIPBOARD_CLEAR_MS = 30_000;
const REVEAL_MS = 30_000;
const HIDDEN_LOCK_MS = 60_000;

const $ = (id) => document.getElementById(id);

// ---------- state ----------
let record = loadRecord();
let session = null;      // { key, data } — hanya ada di memori saat terbuka
let pending = null;      // hasil password benar, menunggu 2FA
let setupState = null;   // { password, secret } saat membuat brankas
let resetState = null;   // { secret } saat mengatur ulang 2FA
let useRecovery = false;
let idleTimer = null;
let hiddenAt = 0;

// ---------- storage ----------
function loadRecord() {
  try { return JSON.parse(localStorage.getItem(STORE_KEY)); } catch { return null; }
}
function saveRecord(r) {
  record = r;
  localStorage.setItem(STORE_KEY, JSON.stringify(r));
}
async function persist() {
  saveRecord(await sealVault(record, session.key, session.data));
}

// ---------- pembatasan percobaan (brute-force) ----------
function lockState() {
  try { return JSON.parse(localStorage.getItem(LOCK_KEY)) || { fails: 0, until: 0 }; } catch { return { fails: 0, until: 0 }; }
}
function lockedSeconds() {
  return Math.max(0, Math.ceil((lockState().until - Date.now()) / 1000));
}
function registerFail() {
  const s = lockState();
  s.fails += 1;
  if (s.fails >= MAX_FREE_FAILS) {
    const delay = Math.min(30_000 * 2 ** (s.fails - MAX_FREE_FAILS), 3_600_000);
    s.until = Date.now() + delay;
  }
  localStorage.setItem(LOCK_KEY, JSON.stringify(s));
}
function resetFails() { localStorage.removeItem(LOCK_KEY); }
function lockMessage() {
  const s = lockedSeconds();
  return s ? `Terlalu banyak percobaan gagal. Coba lagi dalam ${s} detik.` : '';
}

// ---------- UI helpers ----------
const SCREENS = ['screen-setup', 'screen-2fa-setup', 'screen-recovery', 'screen-unlock', 'screen-verify', 'screen-vault', 'screen-settings'];
function show(id) {
  for (const s of SCREENS) $(s).hidden = s !== id;
  $('vault-actions').hidden = !session;
  document.querySelectorAll('.error').forEach((e) => (e.textContent = ''));
  const first = $(id).querySelector('input:not([type=hidden])');
  if (first && !matchMedia('(pointer: coarse)').matches) first.focus();
}

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Memproses…';
  try { return await fn(); } finally { button.disabled = false; button.textContent = label; }
}

function submitBtn(form) { return form.querySelector('button[type=submit]'); }

async function copyText(text, what = 'Disalin') {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what}. Clipboard dibersihkan dalam 30 detik.`);
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_MS);
  } catch {
    toast('Gagal menyalin ke clipboard.');
  }
}

function passwordScore(pw) {
  let score = 0;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (pw.length >= 20) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (/(.)\1{3,}/.test(pw) || /^(password|12345|qwerty)/i.test(pw)) score = Math.max(0, score - 2);
  return Math.min(score, 4); // 0..4
}

function renderQr(secret) {
  const qr = qrcode(0, 'M');
  qr.addData(otpauthUri(secret));
  qr.make();
  $('qr-img').src = qr.createDataURL(6, 2);
  $('totp-secret-text').textContent = secret.match(/.{1,4}/g).join(' ');
}

// ---------- auto-lock ----------
function autoLockMs() { return (session?.data.settings?.autoLockMin || 5) * 60_000; }
function armIdle() {
  clearTimeout(idleTimer);
  if (session) idleTimer = setTimeout(() => lock('Terkunci otomatis karena tidak aktif.'), autoLockMs());
}
['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach((ev) => addEventListener(ev, armIdle, { passive: true }));
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (session && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lock('Terkunci karena aplikasi ditinggalkan.');
});

function lock(msg) {
  session = null;
  pending = null;
  resetState = null;
  clearTimeout(idleTimer);
  $('key-list').replaceChildren();
  if ($('dlg-key').open) $('dlg-key').close();
  $('form-key').reset();
  $('unlock-pw').value = '';
  route();
  if (msg) toast(msg);
}

function route() {
  if (!record) show('screen-setup');
  else if (!session) show('screen-unlock');
  else { show('screen-vault'); renderKeys(); armIdle(); }
}

// ================= SETUP =================
$('setup-pw').addEventListener('input', (e) => {
  const s = passwordScore(e.target.value);
  const m = $('pw-meter');
  m.style.width = `${(s / 4) * 100}%`;
  m.dataset.level = s;
  $('pw-hint').textContent = ['Terlalu lemah', 'Lemah', 'Cukup', 'Kuat', 'Sangat kuat'][s] + ' — minimal 12 karakter.';
});

$('form-setup').addEventListener('submit', (e) => {
  e.preventDefault();
  const pw = $('setup-pw').value;
  if (pw !== $('setup-pw2').value) return void ($('setup-error').textContent = 'Password tidak sama.');
  if (pw.length < 12) return void ($('setup-error').textContent = 'Password minimal 12 karakter.');
  if (passwordScore(pw) < 2) return void ($('setup-error').textContent = 'Password terlalu lemah. Buat lebih panjang/variatif.');
  setupState = { password: pw, secret: generateSecret() };
  $('setup-pw').value = $('setup-pw2').value = '';
  $('twofa-title').textContent = 'Aktifkan 2FA';
  $('twofa-sub').textContent = 'Langkah 2 dari 3 — pindai QR ini dengan aplikasi authenticator (Google Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS…).';
  renderQr(setupState.secret);
  $('setup-otp').value = '';
  show('screen-2fa-setup');
});

let pendingRecoveryCodes = null;
$('form-2fa-setup').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = $('setup-otp').value.trim();
  const target = resetState || setupState;
  if (!target) return;
  const counter = await verifyTotp(target.secret, code);
  if (counter === null) return void ($('twofa-error').textContent = 'Kode salah. Pastikan jam di HP sudah benar.');

  await busy(submitBtn(e.target), async () => {
    if (resetState) {
      session.data.totp = { secret: resetState.secret, lastCounter: counter };
      resetState = null;
      await persist();
      toast('2FA berhasil diatur ulang.');
      show('screen-settings');
      return;
    }
    const codes = generateRecoveryCodes();
    const data = {
      totp: { secret: setupState.secret, lastCounter: counter },
      recovery: await Promise.all(codes.map(hashRecoveryCode)),
      keys: [],
      settings: { autoLockMin: 5 },
      createdAt: new Date().toISOString(),
    };
    const { record: r, key } = await createVault(setupState.password, data);
    setupState = null;
    saveRecord(r);
    session = { key, data };
    showRecoveryCodes(codes);
  });
});

$('btn-2fa-cancel').addEventListener('click', () => {
  if (resetState) { resetState = null; show('screen-settings'); return; }
  setupState = null;
  show('screen-setup');
});

function showRecoveryCodes(codes) {
  pendingRecoveryCodes = codes;
  const ol = $('recovery-list');
  ol.replaceChildren(...codes.map((c) => Object.assign(document.createElement('li'), { textContent: c })));
  show('screen-recovery');
}
$('btn-copy-codes').addEventListener('click', () => pendingRecoveryCodes && copyText(pendingRecoveryCodes.join('\n'), 'Kode pemulihan disalin'));
$('btn-recovery-done').addEventListener('click', () => {
  pendingRecoveryCodes = null;
  $('recovery-list').replaceChildren();
  route();
});

// ================= UNLOCK =================
$('form-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (lockedSeconds()) return void ($('unlock-error').textContent = lockMessage());
  const pw = $('unlock-pw').value;
  await busy($('btn-unlock'), async () => {
    try {
      pending = await openVault(record, pw);
      $('unlock-pw').value = '';
      useRecovery = false;
      updateRecoveryToggle();
      $('verify-otp').value = '';
      show('screen-verify');
    } catch (err) {
      registerFail();
      $('unlock-error').textContent = lockMessage() || err.message;
    }
  });
});

function updateRecoveryToggle() {
  $('verify-label').firstChild.textContent = useRecovery ? 'Kode pemulihan (XXXX-XXXX-XXXX)' : 'Kode 6 digit dari aplikasi authenticator';
  $('verify-otp').inputMode = useRecovery ? 'text' : 'numeric';
  $('btn-toggle-recovery').textContent = useRecovery ? 'Gunakan kode authenticator' : 'Gunakan kode pemulihan';
}
$('btn-toggle-recovery').addEventListener('click', () => {
  useRecovery = !useRecovery;
  updateRecoveryToggle();
  $('verify-otp').value = '';
  $('verify-otp').focus();
});
$('btn-verify-cancel').addEventListener('click', () => { pending = null; show('screen-unlock'); });

/** Memeriksa kode TOTP atau kode pemulihan terhadap data vault. Mengubah data bila cocok. */
async function checkSecondFactor(data, input, allowRecovery) {
  const code = input.trim();
  if (/^\d{6}$/.test(code.replace(/\s/g, ''))) {
    const counter = await verifyTotp(data.totp.secret, code, { lastCounter: data.totp.lastCounter ?? -1 });
    if (counter !== null) { data.totp.lastCounter = counter; return 'totp'; }
    return null;
  }
  if (!allowRecovery) return null;
  const h = await hashRecoveryCode(code);
  const idx = data.recovery.findIndex((x) => timingSafeEqual(x, h));
  if (idx < 0) return null;
  data.recovery.splice(idx, 1); // sekali pakai
  return 'recovery';
}

$('form-verify').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!pending) return show('screen-unlock');
  if (lockedSeconds()) return void ($('verify-error').textContent = lockMessage());
  await busy(submitBtn(e.target), async () => {
    const kind = await checkSecondFactor(pending.data, $('verify-otp').value, useRecovery);
    if (!kind) {
      registerFail();
      $('verify-error').textContent = lockMessage() || (useRecovery ? 'Kode pemulihan tidak valid.' : 'Kode 2FA salah atau sudah dipakai.');
      return;
    }
    resetFails();
    session = pending;
    pending = null;
    await persist(); // simpan lastCounter / kode pemulihan yang terpakai
    route();
    if (kind === 'recovery') toast(`Kode pemulihan dipakai. Tersisa ${session.data.recovery.length}. Segera atur ulang 2FA.`);
  });
});

// ================= VAULT =================
async function renderKeys() {
  if (!session) return;
  const q = $('search').value.trim().toLowerCase();
  const keys = session.data.keys.filter((k) => !q || k.label.toLowerCase().includes(q) || k.type.toLowerCase().includes(q));
  $('empty').hidden = session.data.keys.length > 0;
  $('key-list').replaceChildren(...keys.map(keyItem));
}
$('search').addEventListener('input', renderKeys);

function el(tag, props = {}, ...children) {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...children);
  return n;
}

function keyItem(k) {
  const secretBox = el('pre', { className: 'secret-box', hidden: true });
  let hideTimer;
  const btnReveal = el('button', { type: 'button', className: 'ghost', textContent: 'Tampilkan' });
  btnReveal.onclick = () => {
    const showing = secretBox.hidden;
    secretBox.hidden = !showing;
    secretBox.textContent = showing ? k.secret : '';
    btnReveal.textContent = showing ? 'Sembunyikan' : 'Tampilkan';
    clearTimeout(hideTimer);
    if (showing) hideTimer = setTimeout(() => { secretBox.hidden = true; secretBox.textContent = ''; btnReveal.textContent = 'Tampilkan'; }, REVEAL_MS);
  };
  const btnCopy = el('button', { type: 'button', className: 'ghost', textContent: 'Salin' });
  btnCopy.onclick = () => copyText(k.secret, 'Private key disalin');
  const btnEdit = el('button', { type: 'button', className: 'ghost', textContent: 'Ubah' });
  btnEdit.onclick = () => openKeyDialog(k);
  const btnDel = el('button', { type: 'button', className: 'ghost danger-text', textContent: 'Hapus' });
  btnDel.onclick = async () => {
    if (!confirm(`Hapus "${k.label}"? Tindakan ini tidak bisa dibatalkan.`)) return;
    session.data.keys = session.data.keys.filter((x) => x.id !== k.id);
    await persist();
    renderKeys();
    toast('Dihapus.');
  };

  return el('li', { className: 'key' },
    el('div', { className: 'key-head' },
      el('strong', { textContent: k.label }),
      el('span', { className: 'badge', textContent: k.type })),
    el('div', { className: 'fp', title: 'Sidik jari SHA-256 — untuk mencocokkan tanpa membuka kunci', textContent: `SHA-256 ${k.fingerprint}` }),
    k.notes ? el('p', { className: 'notes', textContent: k.notes }) : '',
    secretBox,
    el('div', { className: 'row wrap' }, btnReveal, btnCopy, btnEdit, btnDel));
}

let editingId = null;
function openKeyDialog(k = null) {
  editingId = k?.id ?? null;
  $('dlg-key-title').textContent = k ? 'Ubah private key' : 'Tambah private key';
  $('key-label').value = k?.label ?? '';
  $('key-type').value = k?.type ?? 'Crypto wallet';
  $('key-secret').value = k?.secret ?? '';
  $('key-notes').value = k?.notes ?? '';
  $('key-error').textContent = '';
  $('dlg-key').showModal();
}
function closeKeyDialog() {
  $('form-key').reset();
  editingId = null;
  $('dlg-key').close();
}
$('btn-add').addEventListener('click', () => openKeyDialog());
$('btn-key-cancel').addEventListener('click', closeKeyDialog);
$('dlg-key').addEventListener('cancel', () => $('form-key').reset());

$('form-key').addEventListener('submit', async (e) => {
  e.preventDefault();
  const label = $('key-label').value.trim();
  const secret = $('key-secret').value.trim();
  if (!label || !secret) return void ($('key-error').textContent = 'Label dan private key wajib diisi.');
  const fp = await fingerprint(secret);
  const dup = session.data.keys.find((x) => x.fingerprint === fp && x.id !== editingId);
  if (dup && !confirm(`Private key yang sama sudah tersimpan sebagai "${dup.label}". Tetap simpan?`)) return;
  const entry = {
    id: editingId ?? toB64(randomBytes(9)),
    label, type: $('key-type').value, secret, notes: $('key-notes').value.trim(), fingerprint: fp,
    createdAt: session.data.keys.find((x) => x.id === editingId)?.createdAt ?? new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const i = session.data.keys.findIndex((x) => x.id === editingId);
  if (i >= 0) session.data.keys[i] = entry; else session.data.keys.push(entry);
  await persist();
  closeKeyDialog();
  renderKeys();
  toast('Tersimpan & terenkripsi.');
});

$('btn-lock').addEventListener('click', () => lock());

// ================= SETTINGS =================
$('btn-settings').addEventListener('click', () => {
  $('rc-count').textContent = session.data.recovery.length;
  $('autolock').value = String(session.data.settings?.autoLockMin || 5);
  document.querySelectorAll('#screen-settings form').forEach((f) => f.reset());
  show('screen-settings');
});
$('btn-settings-close').addEventListener('click', () => route());

$('form-chpw').addEventListener('submit', async (e) => {
  e.preventDefault();
  const oldPw = $('chpw-old').value, n1 = $('chpw-new').value, n2 = $('chpw-new2').value;
  if (n1 !== n2) return void ($('chpw-error').textContent = 'Password baru tidak sama.');
  if (n1.length < 12 || passwordScore(n1) < 2) return void ($('chpw-error').textContent = 'Password baru terlalu lemah (min. 12 karakter).');
  await busy(submitBtn(e.target), async () => {
    try {
      await openVault(record, oldPw);
    } catch {
      registerFail();
      return void ($('chpw-error').textContent = 'Password saat ini salah.');
    }
    const { record: r, key } = await createVault(n1, session.data, PBKDF2_ITERATIONS);
    saveRecord(r);
    session.key = key;
    e.target.reset();
    toast('Master password diganti.');
  });
});

$('form-reset2fa').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (lockedSeconds()) return void ($('reset2fa-error').textContent = lockMessage());
  const kind = await checkSecondFactor(session.data, $('reset2fa-code').value, true);
  if (!kind) { registerFail(); return void ($('reset2fa-error').textContent = lockMessage() || 'Kode tidak valid.'); }
  await persist();
  resetState = { secret: generateSecret() };
  $('twofa-title').textContent = 'Atur ulang 2FA';
  $('twofa-sub').textContent = 'Pindai QR baru ini dengan aplikasi authenticator, lalu hapus entri Seekure yang lama.';
  renderQr(resetState.secret);
  $('setup-otp').value = '';
  show('screen-2fa-setup');
});

$('form-regen').addEventListener('submit', async (e) => {
  e.preventDefault();
  const counter = await verifyTotp(session.data.totp.secret, $('regen-code').value, { lastCounter: session.data.totp.lastCounter });
  if (counter === null) { registerFail(); return void ($('regen-error').textContent = 'Kode 2FA salah.'); }
  session.data.totp.lastCounter = counter;
  const codes = generateRecoveryCodes();
  session.data.recovery = await Promise.all(codes.map(hashRecoveryCode));
  await persist();
  showRecoveryCodes(codes);
});

$('autolock').addEventListener('change', async (e) => {
  session.data.settings = { ...session.data.settings, autoLockMin: Number(e.target.value) };
  await persist();
  armIdle();
  toast('Disimpan.');
});

$('btn-export').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: `seekure-backup-${new Date().toISOString().slice(0, 10)}.json` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Cadangan terenkripsi diekspor.');
});

const startImport = () => $('file-import').click();
$('btn-import').addEventListener('click', startImport);
$('btn-import-start').addEventListener('click', startImport);
$('file-import').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    const r = JSON.parse(await file.text());
    if (r?.v !== 1 || r.kdf?.name !== 'PBKDF2' || !r.iv || !r.ct || !r.kdf.salt) throw new Error();
    if (record && !confirm('Brankas di perangkat ini akan DIGANTI dengan isi cadangan. Lanjutkan?')) return;
    saveRecord(r);
    lock('Cadangan diimpor. Buka dengan master password + 2FA.');
  } catch {
    toast('File cadangan tidak valid.');
  }
});

$('form-wipe').addEventListener('submit', (e) => {
  e.preventDefault();
  if ($('wipe-confirm').value.trim() !== 'HAPUS') return;
  localStorage.removeItem(STORE_KEY);
  localStorage.removeItem(LOCK_KEY);
  record = null;
  lock('Brankas dihapus dari perangkat ini.');
});

// ================= start =================
// Anti-clickjacking: jangan jalan di dalam iframe situs lain.
if (window.top !== window.self) {
  document.body.replaceChildren('Seekure tidak boleh dibuka di dalam frame.');
  throw new Error('framed');
}
if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}
if (navigator.storage?.persist) navigator.storage.persist().catch(() => {});
route();
