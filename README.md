# Seekure 🔐

Aplikasi brankas **private key** untuk **PC dan smartphone**: terenkripsi, berjalan 100% offline, dan dibuka dengan **master password + 2FA**. Faktor kedua bisa berupa kode TOTP dari aplikasi authenticator, atau **kunci fisik** (YubiKey/FIDO2).

Seekure dibuat sebagai **PWA (Progressive Web App)**. Satu kode yang sama bisa di-*install* seperti aplikasi biasa di Windows, macOS, Linux, Android, dan iOS, tanpa app store dan tanpa server.

## Fitur

| | |
|---|---|
| 🔑 **Hash password** | Master password diubah menjadi kunci dengan **PBKDF2-HMAC-SHA-256** (600.000 iterasi, sesuai rekomendasi OWASP) dan salt acak 16 byte |
| 🛡️ **Enkripsi** | Semua isi brankas dienkripsi **AES-256-GCM**. Setiap kali disimpan memakai IV acak baru, dan header ikut diautentikasi |
| 📱 **2FA** | TOTP (RFC 6238), 6 digit, berganti tiap 30 detik. Bisa dipakai dengan Google Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS, dll. Kode yang sudah dipakai tidak bisa dipakai lagi (anti-replay) |
| 🔐 **Kunci fisik (opsional)** | YubiKey 5, SoloKey 2, Google Titan, Feitian, dan kunci FIDO2 lain lewat **WebAuthn PRF (hmac-secret)**. Kunci fisik ikut menjadi **bagian dari kunci enkripsi**: file brankas yang dicuri tidak bisa dibuka walaupun password bocor. Mendukung banyak kunci (utama + cadangan) dan **kunci pemulihan** cetak 160-bit |
| 🧾 **Kode pemulihan** | Ada 8 kode sekali pakai untuk berjaga-jaga kalau HP authenticator hilang. Yang disimpan hanya **hash SHA-256**-nya |
| 🔍 **Sidik jari SHA-256** | Setiap private key diberi sidik jari, jadi Anda bisa mencocokkan key tanpa menampilkannya. Key yang sama terdeteksi sebagai duplikat |
| ⏱️ **Kunci otomatis** | Brankas terkunci sendiri setelah tidak dipakai (1–30 menit, bisa diatur) atau 60 detik setelah aplikasi ditinggalkan |
| 🚫 **Anti brute-force** | Setelah 5 kali gagal, ada jeda yang makin lama (30 detik, lalu 1 menit, 2 menit, … sampai maks. 1 jam) |
| 👁️ **Tampilan & input aman** | Key hanya terlihat selama tombol ditahan, dan layar disamarkan saat aplikasi tidak aktif. Kolom private key dan kode pemulihan **tersamar**, sehingga keyboard HP masuk mode incognito dan tidak mempelajari atau menyimpan isinya |
| 📋 **Clipboard aman** | Key yang disalin dibersihkan dari clipboard setelah 30 detik. Key yang ditampilkan disembunyikan lagi setelah 30 detik |
| 💾 **Cadangan & sinkron** | Ekspor/impor file cadangan yang **tetap terenkripsi**, untuk memindahkan brankas antara PC dan HP |
| ✈️ **Offline** | Tidak ada server, analitik, atau request jaringan. CSP ketat (`default-src 'none'`) |

## Alur pemakaian

1. **Pertama kali dibuka:** buat master password (minimal 12 karakter).
2. **Pindai kode QR** dengan aplikasi authenticator, lalu masukkan kode 6 digit untuk verifikasi.
3. **Catat 8 kode pemulihan** di kertas.
4. **Untuk membuka aplikasi:** masukkan master password, lalu kode 2FA dari authenticator.

## Menjalankan & meng-install

PWA harus dibuka lewat **HTTPS** (atau `localhost`) supaya bisa di-install dan dipakai offline.

**Coba di komputer sendiri:**

```bash
python3 -m http.server 8080
# buka http://localhost:8080
```

**Online via GitHub Pages:** **https://woeatomo.github.io/Seekure/**

Workflow `.github/workflows/pages.yml` menjalankan unit test lalu men-deploy otomatis setiap ada push. Aktifkan sekali saja di **Settings → Pages → Build and deployment → Source: GitHub Actions**. Hosting HTTPS statis lain (Netlify, Cloudflare Pages) juga bisa, karena tidak perlu proses *build*.

> Data brankas tetap hanya tersimpan di perangkat Anda. GitHub Pages hanya mengirimkan file aplikasinya.

**Cara install:**

- **PC (Chrome / Edge):** klik ikon *Install* di address bar, atau menu ⋮ → *Install Seekure*.
- **Android (Chrome):** menu ⋮ → *Add to Home screen / Install app*.
- **iPhone / iPad (Safari):** tombol Share → *Add to Home Screen*.

Setelah di-install, aplikasi tetap berjalan tanpa internet.

### Versi offline untuk PC (tidak update otomatis)

Versi online di github.io selalu mengambil kode terbaru. Kalau akun GitHub pembuatnya sampai dibobol, kode jahat bisa ikut terkirim ke semua pengguna. Untuk PC, ada **versi offline** yang berjalan dari komputer Anda sendiri dan hanya berubah kalau Anda yang menggantinya.

1. Unduh `seekure-offline-vX.Y.Z.zip` dari halaman **[Releases](https://github.com/woeatomo/Seekure/releases)**.
2. Periksa hash SHA-256-nya: bandingkan dengan `SHA256SUMS.txt` di halaman rilis yang sama (perintahnya ada di `BACA-SAYA.txt`).
3. Ekstrak, lalu jalankan:
   - **Windows:** klik dua kali `Jalankan-Seekure-Windows.cmd`. Ini memakai PowerShell bawaan Windows, tidak perlu instalasi apa pun.
   - **macOS/Linux:** `sh jalankan-seekure.sh` (butuh python3).
4. Browser terbuka di `http://localhost:8737/`. Pindahkan brankas lewat **Ekspor/Impor cadangan**.

Paketnya **reproducible**: siapa pun bisa checkout tag yang sama, menjalankan `sh scripts/build-offline.sh`, dan mendapatkan zip dengan hash yang identik. Server lokalnya hanya bisa diakses dari komputer itu sendiri, hanya melayani folder `app/`, dan sudah diuji otomatis di Windows, macOS, dan Linux.

> Kunci fisik terikat ke alamat web. Kunci yang didaftarkan di github.io tidak bekerja di `localhost`. Setelah impor, buka brankas dengan kunci pemulihan, lalu daftarkan kunci fisik lagi untuk alamat ini.

**Membuat rilis baru:** naikkan `APP_VERSION` di `js/version.js` lalu commit. Setelah itu buka GitHub → **Releases → Draft a new release**, buat tag `vX.Y.Z` (harus sama dengan `APP_VERSION`), lalu **Publish**. Bisa juga dengan push tag `vX.Y.Z`. Workflow `offline.yml` akan membangun paket, mengujinya di 3 OS, lalu melampirkan zip + `SHA256SUMS.txt` ke Release tersebut dalam beberapa menit.

### Memakai brankas yang sama di PC dan HP

Data tersimpan di perangkat masing-masing, tidak ada cloud. Untuk memindahkan brankas:

1. Di perangkat A: **Pengaturan → Cadangan → Ekspor cadangan**.
2. Pindahkan file `.json` itu ke perangkat B (lewat kabel atau flashdisk lebih aman).
3. Di perangkat B: **Impor cadangan**, lalu buka dengan master password dan 2FA yang sama.

## Struktur proyek

```
index.html            UI (semua layar)
css/style.css         Tampilan responsif + mode gelap
js/crypto.js          PBKDF2, HKDF, AES-GCM, SHA-256, kunci fisik, pemulihan
js/webauthn.js        Kunci fisik via WebAuthn PRF (hmac-secret)
js/totp.js            TOTP/HOTP (RFC 4226/6238), base32, URI otpauth
js/app.js             Logika aplikasi
sw.js                 Service worker (offline)
js/version.js         Nomor versi (dicek saat rilis)
offline/              Launcher versi offline (Windows .cmd/PowerShell, macOS/Linux .sh)
scripts/              Build paket offline reproducible + uji server lokal
vendor/qrcode.js      Generator QR (qrcode-generator 1.4.4, MIT, © Kazuhiko Arase)
tests/                Unit test + uji end-to-end di browser
```

## Pengujian

```bash
npm test         # unit test: kripto, vektor uji resmi RFC 6238, anti-replay, deteksi manipulasi data
npm run e2e      # alur lengkap di Chromium (desktop + Pixel 7) via Playwright, termasuk
                 # YubiKey virtual: daftar, kunci cadangan, hapus, kunci pemulihan, nonaktifkan
```

## Kunci fisik (YubiKey / FIDO2)

Aktifkan lewat **Pengaturan → Kunci fisik**. Setelah aktif, membuka brankas butuh **master password + sentuhan kunci fisik (dengan PIN kunci)**. Faktor ini menggantikan kode TOTP.

```
master password ──PBKDF2-SHA-256 (600k)──► membuka PK (32 byte acak)
kunci fisik     ──WebAuthn PRF → HKDF───► membuka HK (32 byte acak)
kunci pemulihan ──HKDF──────────────────► membuka HK (cadangan bila semua kunci hilang)

kunci data = HKDF-SHA-256(PK ‖ HK)  →  AES-256-GCM
```

- **Daftarkan minimal 2 kunci** (utama + cadangan) dan simpan di tempat berbeda.
- **Kunci pemulihan** (32 karakter) ditampilkan satu kali saat mengaktifkan. Tulis di kertas dan simpan terpisah dari kunci fisik.
- **PIN kunci selalu diminta.** Nilai *hmac-secret* berbeda antara dengan PIN dan tanpa PIN, jadi PIN diwajibkan agar hasilnya konsisten. Bonusnya, kunci yang dicuri tidak bisa dipakai tanpa PIN.
- **Kunci terikat ke domain.** Kunci yang didaftarkan di `woeatomo.github.io` hanya bekerja di domain itu, termasuk di perangkat lain setelah impor cadangan.
- **Dukungan browser:** Chrome/Edge di Windows, macOS, Linux, dan Android (USB/NFC). Dukungan di Safari/iOS untuk kunci fisik eksternal masih terbatas. Bila tidak didukung, brankas tetap bisa dibuka dengan kunci pemulihan.
- **Kembali ke mode TOTP:** pilih **Nonaktifkan kunci fisik**, lalu pindai QR 2FA yang baru.

## Model keamanan (harap dibaca)

- **Kekuatan dasar ada di master password.** Siapa pun yang mendapat file brankas harus menebak password lewat PBKDF2 600k iterasi. Gunakan password yang panjang dan unik.
- **Mode TOTP:** 2FA berfungsi sebagai gerbang tingkat aplikasi. Rahasia TOTP disimpan di dalam brankas terenkripsi, karena kode TOTP selalu berganti dan tidak bisa dijadikan kunci enkripsi. Penyerang yang punya file brankas **dan** password bisa mendekripsi tanpa kode TOTP.
- **Mode kunci fisik:** menutup celah di atas. Tanpa kunci fisik terdaftar (atau kunci pemulihan), isi brankas **tidak bisa didekripsi** walaupun file dan password sama-sama bocor.
- **Batas percobaan gagal** disimpan di `localStorage`. Batas ini menghambat percobaan lewat aplikasi, tetapi tidak menghentikan penyerang yang menyalin file brankas. Yang melindungi dalam kasus itu adalah PBKDF2 dan kunci fisik.
- **Lupa master password = data tidak bisa dipulihkan.** Ini disengaja. Hal yang sama berlaku bila semua kunci fisik **dan** kunci pemulihan hilang.
- **Lindungi perangkat Anda.** Malware atau keylogger di perangkat bisa membaca apa pun yang Anda ketik, dan ini berlaku untuk semua aplikasi password manager.
- **Hapus data situs/browser = brankas terhapus.** Rutinlah membuat cadangan.
