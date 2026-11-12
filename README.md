# Seekure 🔐

Aplikasi brankas **private key** untuk **PC dan smartphone**: terenkripsi, berjalan 100% offline, dan dibuka dengan **master password + 2FA (TOTP)**.

Seekure dibuat sebagai **PWA (Progressive Web App)**. Satu kode yang sama bisa di-*install* seperti aplikasi biasa di Windows, macOS, Linux, Android, dan iOS, tanpa app store dan tanpa server.

## Fitur

| | |
|---|---|
| 🔑 **Hash password** | Master password diubah menjadi kunci dengan **PBKDF2-HMAC-SHA-256** (600.000 iterasi, sesuai rekomendasi OWASP) dan salt acak 16 byte |
| 🛡️ **Enkripsi** | Semua isi brankas dienkripsi **AES-256-GCM**. Setiap kali disimpan memakai IV acak baru, dan header ikut diautentikasi |
| 📱 **2FA** | TOTP (RFC 6238), 6 digit, berganti tiap 30 detik. Bisa dipakai dengan Google Authenticator, Microsoft Authenticator, Authy, Aegis, 2FAS, dll. Kode yang sudah dipakai tidak bisa dipakai lagi (anti-replay) |
| 🧾 **Kode pemulihan** | Ada 8 kode sekali pakai untuk berjaga-jaga kalau HP authenticator hilang. Yang disimpan hanya **hash SHA-256**-nya |
| 🔍 **Sidik jari SHA-256** | Setiap private key diberi sidik jari, jadi Anda bisa mencocokkan key tanpa menampilkannya. Key yang sama terdeteksi sebagai duplikat |
| ⏱️ **Kunci otomatis** | Brankas terkunci sendiri setelah tidak dipakai (1–30 menit, bisa diatur) atau 60 detik setelah aplikasi ditinggalkan |
| 🚫 **Anti brute-force** | Setelah 5 kali gagal, ada jeda yang makin lama (30 detik, lalu 1 menit, 2 menit, … sampai maks. 1 jam) |
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

**Supaya bisa di-install di HP:** host folder ini di layanan HTTPS statis mana saja, misalnya **GitHub Pages** (Settings → Pages → *Deploy from branch*), Netlify, atau Cloudflare Pages. Semua file bersifat statis dan tidak perlu proses *build*.

**Cara install:**

- **PC (Chrome / Edge):** klik ikon *Install* di address bar, atau menu ⋮ → *Install Seekure*.
- **Android (Chrome):** menu ⋮ → *Add to Home screen / Install app*.
- **iPhone / iPad (Safari):** tombol Share → *Add to Home Screen*.

Setelah di-install, aplikasi tetap berjalan tanpa internet.

### Memakai brankas yang sama di PC dan HP

Data tersimpan di perangkat masing-masing, tidak ada cloud. Untuk memindahkan brankas:

1. Di perangkat A: **Pengaturan → Cadangan → Ekspor cadangan**.
2. Pindahkan file `.json` itu ke perangkat B (lewat kabel atau flashdisk lebih aman).
3. Di perangkat B: **Impor cadangan**, lalu buka dengan master password dan 2FA yang sama.

## Struktur proyek

```
index.html            UI (semua layar)
css/style.css         Tampilan responsif + mode gelap
js/crypto.js          PBKDF2, AES-GCM, SHA-256, kode pemulihan
js/totp.js            TOTP/HOTP (RFC 4226/6238), base32, URI otpauth
js/app.js             Logika aplikasi
sw.js                 Service worker (offline)
vendor/qrcode.js      Generator QR (qrcode-generator 1.4.4, MIT, © Kazuhiko Arase)
tests/                Unit test + uji end-to-end di browser
```

## Pengujian

```bash
npm test         # unit test: kripto, vektor uji resmi RFC 6238, anti-replay, deteksi manipulasi data
npm run e2e      # alur lengkap di Chromium (desktop + Pixel 7) via Playwright
```

## Model keamanan (harap dibaca)

- **Kekuatan utama ada di master password.** Siapa pun yang mendapat file brankas harus menebak password lewat PBKDF2 600k iterasi. Gunakan password yang panjang dan unik.
- **2FA di Seekure adalah gerbang tingkat aplikasi.** Rahasia TOTP disimpan **di dalam** brankas terenkripsi, karena kode TOTP selalu berganti dan tidak bisa dijadikan kunci enkripsi. Akibatnya, 2FA melindungi dari orang yang tahu password Anda dan memegang perangkat Anda lewat aplikasi ini. Tetapi penyerang yang sudah punya file brankas **dan** password bisa mendekripsi tanpa 2FA. Untuk benar-benar mengunci di level kriptografi diperlukan kunci perangkat keras (misalnya YubiKey/WebAuthn PRF), yang bisa jadi pengembangan berikutnya.
- **Batas percobaan gagal** disimpan di `localStorage`. Batas ini menghambat percobaan lewat aplikasi, tetapi tidak menghentikan penyerang yang menyalin file brankas. Yang melindungi dalam kasus itu adalah PBKDF2.
- **Lupa master password = data tidak bisa dipulihkan.** Ini disengaja.
- **Lindungi perangkat Anda.** Malware atau keylogger di perangkat bisa membaca apa pun yang Anda ketik, dan ini berlaku untuk semua aplikasi password manager.
- **Hapus data situs/browser = brankas terhapus.** Rutinlah membuat cadangan.
