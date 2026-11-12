import {
  createVault, sealVault, unlockPassword, unlockHardware, unlockRecoveryKey, changePassword,
  enableHardware, addHardwareKey, removeHardwareKey, regenerateRecoveryKey, disableHardware,
  isValidRecord, randomBytes, toB64, generateRecoveryCodes, hashRecoveryCode, timingSafeEqual, fingerprint,
} from './crypto.js';
import { generateSecret, verifyTotp, otpauthUri } from './totp.js';
import { hardwareSupported, registerKey, evaluateKey, slotsForThisSite } from './webauthn.js';
import { APP_VERSION } from './version.js';

const STORE_KEY = 'seekure.vault';
const LOCK_KEY = 'seekure.lockout';
const MAX_FREE_FAILS = 5;
const CLIPBOARD_CLEAR_MS = 30_000;
const REVEAL_MS = 30_000;
const HIDDEN_LOCK_MS = 60_000;

const $ = (id) => document.getElementById(id);

// ---------- state ----------
let record = loadRecord();
let session = null;      // { sess, data }: hanya ada di memori saat brankas terbuka
let pending = null;      // { sess, data?, needsHardware? }: password benar, menunggu faktor ke-2
let setupState = null;   // { password, secret } saat membuat brankas
let resetState = null;   // { secret, disableHw? } saat mengatur ulang 2FA
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
  saveRecord(await sealVault(session.sess, session.data));
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

/** Memastikan master password benar (untuk tindakan sensitif saat brankas terbuka). */
async function verifyPassword(pw) {
  if (lockedSeconds()) return false;
  try {
    await unlockPassword(record, pw);
    return true;
  } catch {
    registerFail();
    return false;
  }
}

// ---------- UI helpers ----------
const SCREENS = ['screen-setup', 'screen-2fa-setup', 'screen-recovery', 'screen-unlock', 'screen-verify',
  'screen-hw', 'screen-rk-show', 'screen-vault', 'screen-settings'];
function show(id) {
  maskAll();
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
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}

async function busy(button, fn, label = 'Memproses…') {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try { return await fn(); } finally { button.disabled = false; button.textContent = original; }
}

function submitBtn(form) { return form.querySelector('button[type=submit]'); }

function el(tag, props = {}, ...children) {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...children);
  return n;
}

// ---------- kolom rahasia tersamar ----------
// Kolom type="password" membuat keyboard HP (Gboard, SwiftKey, dll.) masuk mode
// incognito: isi tidak dipelajari, tidak disarankan ulang, dan tidak masuk riwayat.
function setMasked(field, masked) {
  field.querySelectorAll('input').forEach((i) => { i.type = masked ? 'password' : 'text'; });
  field.querySelectorAll('textarea').forEach((t) => t.classList.toggle('masked', masked));
  const eye = field.querySelector('.eye');
  eye.setAttribute('aria-pressed', String(!masked));
  eye.textContent = masked ? '👁' : '🙈';
}
function maskAll() { document.querySelectorAll('.secret-field').forEach((f) => setMasked(f, true)); }
document.querySelectorAll('.secret-field .eye').forEach((eye) => {
  eye.addEventListener('click', () => {
    const field = eye.closest('.secret-field');
    setMasked(field, eye.getAttribute('aria-pressed') === 'true');
  });
});

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

const fmtDate = (iso) => new Date(iso).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' });

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

// ---------- privasi layar ----------
const revealMode = () => session?.data.settings?.revealMode ?? 'hold';
const privacyBlurOn = () => session?.data.settings?.privacyBlur ?? true;
const secretHiders = new Set();
function hideAllSecrets() { for (const hide of secretHiders) hide(); }
function setPrivacy(on) {
  document.body.classList.toggle('privacy', Boolean(on && session && privacyBlurOn()));
}
addEventListener('blur', () => { hideAllSecrets(); setPrivacy(true); });
addEventListener('focus', () => setPrivacy(false));
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hideAllSecrets(); setPrivacy(true); } else if (document.hasFocus()) setPrivacy(false);
});
addEventListener('pagehide', hideAllSecrets);

function lock(msg) {
  session = null;
  pending = null;
  resetState = null;
  clearTimeout(idleTimer);
  hideAllSecrets();
  secretHiders.clear();
  setPrivacy(false);
  $('key-list').replaceChildren();
  $('hw-list').replaceChildren();
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
  show2faSetup(setupState.secret, 'Aktifkan 2FA',
    'Langkah 2 dari 3 — pindai QR ini dengan aplikasi authenticator (Google Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS…).');
});

function show2faSetup(secret, title, sub) {
  $('twofa-title').textContent = title;
  $('twofa-sub').textContent = sub;
  renderQr(secret);
  $('setup-otp').value = '';
  show('screen-2fa-setup');
}

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
      const { disableHw } = resetState;
      if (disableHw) disableHardware(session.sess);
      session.data.totp = { secret: resetState.secret, lastCounter: counter };
      resetState = null;
      await persist();
      toast(disableHw ? 'Kunci fisik dinonaktifkan. Brankas kini memakai password + TOTP.' : '2FA berhasil diatur ulang.');
      openSettings();
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
    const { record: r, sess } = await createVault(setupState.password, data);
    setupState = null;
    saveRecord(r);
    session = { sess, data };
    showRecoveryCodes(codes);
  });
});

$('btn-2fa-cancel').addEventListener('click', () => {
  if (resetState) { resetState = null; openSettings(); return; }
  setupState = null;
  show('screen-setup');
});

function showRecoveryCodes(codes) {
  pendingRecoveryCodes = codes;
  $('recovery-list').replaceChildren(...codes.map((c) => el('li', { textContent: c })));
  show('screen-recovery');
}
$('btn-copy-codes').addEventListener('click', () => pendingRecoveryCodes && copyText(pendingRecoveryCodes.join('\n'), 'Kode pemulihan disalin'));
$('btn-recovery-done').addEventListener('click', () => {
  pendingRecoveryCodes = null;
  $('recovery-list').replaceChildren();
  route();
});

// ================= UNLOCK: langkah 1 (password) =================
$('form-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (lockedSeconds()) return void ($('unlock-error').textContent = lockMessage());
  const pw = $('unlock-pw').value;
  await busy($('btn-unlock'), async () => {
    try {
      pending = await unlockPassword(record, pw);
    } catch (err) {
      registerFail();
      $('unlock-error').textContent = lockMessage() || err.message;
      return;
    }
    $('unlock-pw').value = '';
    if (pending.needsHardware) {
      showHwStep();
    } else {
      useRecovery = false;
      updateRecoveryToggle();
      $('verify-otp').value = '';
      show('screen-verify');
    }
  });
});

async function finishUnlock(data) {
  resetFails();
  session = { sess: pending.sess, data };
  pending = null;
  await persist(); // simpan lastCounter / kode terpakai / migrasi format
  route();
}

// ================= UNLOCK: langkah 2a (kode TOTP / kode pemulihan) =================
function updateRecoveryToggle() {
  $('verify-label').firstChild.textContent = useRecovery ? 'Kode pemulihan (XXXX-XXXX-XXXX)' : 'Kode 6 digit dari aplikasi authenticator';
  $('verify-otp').inputMode = useRecovery ? 'text' : 'numeric';
  $('verify-otp').type = useRecovery ? 'password' : 'text';
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
  if (!pending?.data) return show('screen-unlock');
  if (lockedSeconds()) return void ($('verify-error').textContent = lockMessage());
  await busy(submitBtn(e.target), async () => {
    const kind = await checkSecondFactor(pending.data, $('verify-otp').value, useRecovery);
    if (!kind) {
      registerFail();
      $('verify-error').textContent = lockMessage() || (useRecovery ? 'Kode pemulihan tidak valid.' : 'Kode 2FA salah atau sudah dipakai.');
      return;
    }
    await finishUnlock(pending.data);
    if (kind === 'recovery') toast(`Kode pemulihan dipakai. Tersisa ${session.data.recovery.length}. Segera atur ulang 2FA.`);
  });
});

// ================= UNLOCK: langkah 2b (kunci fisik / kunci pemulihan) =================
function showHwStep() {
  $('form-rk').hidden = true;
  $('btn-hw-unlock').hidden = false;
  $('btn-toggle-rk').textContent = 'Kunci fisik hilang? Gunakan kunci pemulihan';
  $('rk-input').value = '';
  show('screen-hw');
  if (!hardwareSupported()) $('hw-error').textContent = 'Browser ini tidak mendukung kunci fisik. Gunakan Chrome/Edge terbaru, atau buka dengan kunci pemulihan.';
}

$('btn-hw-unlock').addEventListener('click', async (e) => {
  if (!pending?.needsHardware) return show('screen-unlock');
  $('hw-error').textContent = '';
  await busy(e.currentTarget, async () => {
    try {
      const slots = slotsForThisSite(pending.sess.hw.slots);
      if (!slots.length) {
        const sites = [...new Set(pending.sess.hw.slots.map((s) => s.rp))].join(', ');
        throw new Error(`Kunci fisik brankas ini didaftarkan untuk ${sites}, bukan alamat ini. Buka dengan kunci pemulihan, lalu daftarkan kunci fisik untuk alamat ini di Pengaturan.`);
      }
      const { id, prf } = await evaluateKey(slots);
      const data = await unlockHardware(record, pending.sess, id, prf);
      await finishUnlock(data);
    } catch (err) {
      $('hw-error').textContent = err.message;
    }
  }, 'Sentuh kunci fisik Anda…');
});

$('btn-toggle-rk').addEventListener('click', () => {
  const toRk = $('form-rk').hidden;
  $('form-rk').hidden = !toRk;
  $('btn-hw-unlock').hidden = toRk;
  $('btn-toggle-rk').textContent = toRk ? 'Gunakan kunci fisik' : 'Kunci fisik hilang? Gunakan kunci pemulihan';
  $('hw-error').textContent = '';
  if (toRk) $('rk-input').focus();
});

$('form-rk').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!pending?.needsHardware) return show('screen-unlock');
  if (lockedSeconds()) return void ($('hw-error').textContent = lockMessage());
  await busy(submitBtn(e.target), async () => {
    try {
      const data = await unlockRecoveryKey(record, pending.sess, $('rk-input').value);
      await finishUnlock(data);
      toast('Dibuka dengan kunci pemulihan. Jika kunci fisik hilang, hapus dari daftar dan daftarkan kunci baru.');
    } catch (err) {
      registerFail();
      $('hw-error').textContent = lockMessage() || err.message;
    }
  });
});

$('btn-hw-cancel').addEventListener('click', () => { pending = null; show('screen-unlock'); });

// ================= VAULT =================
function renderKeys() {
  if (!session) return;
  const q = $('search').value.trim().toLowerCase();
  const keys = session.data.keys.filter((k) => !q || k.label.toLowerCase().includes(q) || k.type.toLowerCase().includes(q));
  $('empty').hidden = session.data.keys.length > 0;
  secretHiders.clear();
  $('key-list').replaceChildren(...keys.map(keyItem));
}
$('search').addEventListener('input', renderKeys);

function keyItem(k) {
  const secretBox = el('pre', { className: 'secret-box', hidden: true });
  const hold = revealMode() === 'hold';
  const btnReveal = el('button', { type: 'button', className: hold ? 'ghost hold-btn' : 'ghost', textContent: hold ? 'Tahan untuk lihat' : 'Tampilkan' });
  let hideTimer;
  const setShown = (on) => {
    clearTimeout(hideTimer);
    secretBox.hidden = !on;
    secretBox.textContent = on ? k.secret : '';
    btnReveal.classList.toggle('active', on && hold);
    if (!hold) btnReveal.textContent = on ? 'Sembunyikan' : 'Tampilkan';
    if (on && !hold) hideTimer = setTimeout(() => setShown(false), REVEAL_MS);
  };
  const hide = () => setShown(false);
  secretHiders.add(hide);

  if (hold) {
    // Hanya terlihat selama tombol ditekan (mouse, sentuh, atau Spasi/Enter).
    btnReveal.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      btnReveal.setPointerCapture?.(e.pointerId);
      setShown(true);
    });
    for (const ev of ['pointerup', 'pointercancel', 'lostpointercapture', 'blur']) btnReveal.addEventListener(ev, hide);
    btnReveal.addEventListener('contextmenu', (e) => e.preventDefault());
    btnReveal.addEventListener('keydown', (e) => {
      if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) { e.preventDefault(); setShown(true); }
    });
    btnReveal.addEventListener('keyup', (e) => { if (e.key === ' ' || e.key === 'Enter') hide(); });
  } else {
    btnReveal.onclick = () => setShown(secretBox.hidden);
  }

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

// Kunci SSH/PGP terdiri dari banyak baris; kolom password hanya satu baris.
const MULTILINE_TYPES = new Set(['SSH', 'PGP']);
const secretInput = () => ($('key-secret-multi').hidden ? $('key-secret') : $('key-secret-multi'));
function setSecretMode(multi) {
  const value = secretInput().value;
  $('key-secret').hidden = multi;
  $('key-secret').required = !multi;
  $('key-secret-multi').hidden = !multi;
  $('key-secret-multi').required = multi;
  $('key-secret').value = multi ? '' : value;
  $('key-secret-multi').value = multi ? value : '';
}
$('key-type').addEventListener('change', () => {
  setSecretMode(MULTILINE_TYPES.has($('key-type').value) || secretInput().value.includes('\n'));
});

let editingId = null;
function openKeyDialog(k = null) {
  editingId = k?.id ?? null;
  $('dlg-key-title').textContent = k ? 'Ubah private key' : 'Tambah private key';
  $('key-label').value = k?.label ?? '';
  $('key-type').value = k?.type ?? 'Crypto wallet';
  $('key-secret').value = '';
  $('key-secret-multi').value = k?.secret ?? '';
  $('key-secret-multi').hidden = false;
  setSecretMode(MULTILINE_TYPES.has($('key-type').value) || (k?.secret ?? '').includes('\n'));
  maskAll();
  $('key-notes').value = k?.notes ?? '';
  $('key-error').textContent = '';
  $('dlg-key').showModal();
}
function closeKeyDialog() {
  $('form-key').reset();
  $('key-secret-multi').value = '';
  maskAll();
  editingId = null;
  $('dlg-key').close();
}
$('btn-add').addEventListener('click', () => openKeyDialog());
$('btn-key-cancel').addEventListener('click', closeKeyDialog);
$('dlg-key').addEventListener('cancel', () => $('form-key').reset());

$('form-key').addEventListener('submit', async (e) => {
  e.preventDefault();
  const label = $('key-label').value.trim();
  const secret = secretInput().value.trim();
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
function openSettings() {
  $('rc-count').textContent = session.data.recovery.length;
  $('autolock').value = String(session.data.settings?.autoLockMin || 5);
  document.querySelectorAll('#screen-settings form').forEach((f) => f.reset());
  $('reveal-mode').value = revealMode();
  $('privacy-blur').checked = privacyBlurOn();
  const offline = ['localhost', '127.0.0.1'].includes(location.hostname);
  $('app-version').textContent = `Seekure v${APP_VERSION} · ${offline ? 'versi offline (tidak update otomatis)' : 'versi online (update otomatis)'}`;
  renderHwSection();
  show('screen-settings');
}
$('btn-settings').addEventListener('click', openSettings);
$('btn-settings-close').addEventListener('click', () => route());

$('form-chpw').addEventListener('submit', async (e) => {
  e.preventDefault();
  const oldPw = $('chpw-old').value, n1 = $('chpw-new').value, n2 = $('chpw-new2').value;
  if (n1 !== n2) return void ($('chpw-error').textContent = 'Password baru tidak sama.');
  if (n1.length < 12 || passwordScore(n1) < 2) return void ($('chpw-error').textContent = 'Password baru terlalu lemah (min. 12 karakter).');
  await busy(submitBtn(e.target), async () => {
    if (!(await verifyPassword(oldPw))) return void ($('chpw-error').textContent = lockMessage() || 'Password saat ini salah.');
    await changePassword(session.sess, n1);
    await persist();
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
  show2faSetup(resetState.secret, 'Atur ulang 2FA', 'Pindai QR baru ini dengan aplikasi authenticator, lalu hapus entri Seekure yang lama.');
});

$('form-regen').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (lockedSeconds()) return void ($('regen-error').textContent = lockMessage());
  const counter = await verifyTotp(session.data.totp.secret, $('regen-code').value, { lastCounter: session.data.totp.lastCounter });
  if (counter === null) { registerFail(); return void ($('regen-error').textContent = lockMessage() || 'Kode 2FA salah.'); }
  session.data.totp.lastCounter = counter;
  const codes = generateRecoveryCodes();
  session.data.recovery = await Promise.all(codes.map(hashRecoveryCode));
  await persist();
  showRecoveryCodes(codes);
});

async function saveSetting(patch) {
  session.data.settings = { ...session.data.settings, ...patch };
  await persist();
  toast('Disimpan.');
}
$('reveal-mode').addEventListener('change', (e) => saveSetting({ revealMode: e.target.value }));
$('privacy-blur').addEventListener('change', (e) => saveSetting({ privacyBlur: e.target.checked }));

$('autolock').addEventListener('change', async (e) => {
  session.data.settings = { ...session.data.settings, autoLockMin: Number(e.target.value) };
  await persist();
  armIdle();
  toast('Disimpan.');
});

// ---------- kunci fisik ----------
function renderHwSection() {
  const on = Boolean(session.sess.hw);
  const supported = hardwareSupported();
  $('hw-status').textContent = on ? 'Aktif' : 'Nonaktif';
  $('hw-status').classList.toggle('on', on);
  $('hw-unsupported').hidden = supported;
  $('hw-off').hidden = on || !supported;
  $('hw-on').hidden = !on;
  // Dalam mode kunci fisik, pengaturan TOTP tidak dipakai untuk membuka brankas.
  $('totp-reset-details').hidden = on;
  $('totp-codes-details').hidden = on;
  if (!on) return void $('hw-list').replaceChildren();

  const slots = session.sess.hw.slots;
  $('hw-list').replaceChildren(...slots.map((s) => {
    const del = el('button', { type: 'button', className: 'ghost danger-text', textContent: 'Hapus', disabled: slots.length <= 1 });
    del.title = slots.length <= 1 ? 'Minimal harus ada satu kunci fisik' : '';
    del.onclick = async () => {
      if (!confirm(`Hapus kunci "${s.label}" dari brankas? Kunci ini tidak akan bisa membuka brankas lagi.`)) return;
      removeHardwareKey(session.sess, s.id);
      await persist();
      renderHwSection();
      toast('Kunci fisik dihapus.');
    };
    return el('li', {}, el('div', {}, el('strong', { textContent: `🔑 ${s.label}` }), el('small', { textContent: `Didaftarkan ${fmtDate(s.createdAt)}${s.rp ? ` · untuk ${s.rp}` : ''}` })), del);
  }));
}

let pendingRk = null;
function showRecoveryKey(code) {
  pendingRk = code;
  $('rk-show').textContent = code;
  $('rk-confirm').value = '';
  show('screen-rk-show');
}
$('btn-copy-rk').addEventListener('click', () => pendingRk && copyText(pendingRk, 'Kunci pemulihan disalin'));
$('btn-rk-done').addEventListener('click', () => {
  if (!pendingRk) return openSettings();
  if ($('rk-confirm').value.trim().toUpperCase() !== pendingRk.slice(-4)) {
    return void ($('rk-show-error').textContent = '4 karakter terakhir tidak cocok. Periksa catatan Anda.');
  }
  pendingRk = null;
  $('rk-show').textContent = '';
  openSettings();
  toast('Kunci fisik aktif. Daftarkan juga kunci cadangan.');
});

$('form-hw-enable').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('hw-enable-error');
  await busy(submitBtn(e.target), async () => {
    if (lockedSeconds()) return void (err.textContent = lockMessage());
    try {
      // WebAuthn dipanggil langsung setelah tombol ditekan (Safari mewajibkan gestur pengguna),
      // baru setelah itu password diperiksa.
      const key = await registerKey($('hw-label').value.trim() || 'Kunci fisik');
      if (!(await verifyPassword($('hw-enable-pw').value))) return void (err.textContent = lockMessage() || 'Master password salah.');
      const code = await enableHardware(session.sess, key);
      await persist();
      showRecoveryKey(code);
    } catch (ex) {
      err.textContent = ex.message;
    }
  }, 'Sentuh kunci fisik Anda…');
});

$('form-hw-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  await busy(submitBtn(e.target), async () => {
    try {
      const key = await registerKey($('hw-add-label').value.trim() || 'Kunci cadangan', slotsForThisSite(session.sess.hw.slots).map((s) => s.id));
      await addHardwareKey(session.sess, key);
      await persist();
      renderHwSection();
      toast(`Kunci "${key.label}" terdaftar.`);
    } catch (ex) {
      $('hw-add-error').textContent = ex.message;
    }
  }, 'Sentuh kunci cadangan…');
});

$('form-hw-rk').addEventListener('submit', async (e) => {
  e.preventDefault();
  await busy(submitBtn(e.target), async () => {
    if (!(await verifyPassword($('hw-rk-pw').value))) return void ($('hw-rk-error').textContent = lockMessage() || 'Master password salah.');
    const code = await regenerateRecoveryKey(session.sess);
    await persist();
    showRecoveryKey(code);
  });
});

$('form-hw-disable').addEventListener('submit', async (e) => {
  e.preventDefault();
  await busy(submitBtn(e.target), async () => {
    if (!(await verifyPassword($('hw-disable-pw').value))) return void ($('hw-disable-error').textContent = lockMessage() || 'Master password salah.');
    // Kunci fisik baru dinonaktifkan setelah 2FA TOTP baru terverifikasi.
    resetState = { secret: generateSecret(), disableHw: true };
    show2faSetup(resetState.secret, 'Kembali ke 2FA TOTP', 'Pindai QR ini dengan aplikasi authenticator. Kunci fisik baru dinonaktifkan setelah kode terverifikasi.');
  });
});

// ---------- cadangan ----------
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
  let r;
  try { r = JSON.parse(await file.text()); } catch { r = null; }
  if (!isValidRecord(r)) return toast('File cadangan tidak valid.');
  if (record && !confirm('Brankas di perangkat ini akan DIGANTI dengan isi cadangan. Lanjutkan?')) return;
  saveRecord(r);
  lock(r.hw ? 'Cadangan diimpor. Buka dengan master password + kunci fisik.' : 'Cadangan diimpor. Buka dengan master password + 2FA.');
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
