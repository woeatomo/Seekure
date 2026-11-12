#!/bin/sh
# Memeriksa server lokal versi offline: file app dilayani benar, file di luar folder app tidak bisa diakses.
# Pakai: sh scripts/test-offline-server.sh [URL]
set -u
URL=${1:-http://localhost:8737}
fail=0
check() { # deskripsi, kondisi
  if [ "$2" = ok ]; then echo "  ok   $1"; else echo "  GAGAL $1"; fail=1; fi
}
code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' "$URL$1"; }
ctype() { curl -s -o /dev/null -w '%{content_type}' "$URL$1"; }

for i in $(seq 1 60); do curl -s -o /dev/null "$URL/" && break; sleep 1; done

body=$(curl -s "$URL/")
case "$body" in *"<title>Seekure</title>"*) r=ok ;; *) r=no ;; esac; check "halaman utama" $r
for f in js/app.js js/crypto.js js/webauthn.js js/version.js sw.js vendor/qrcode.js css/style.css icons/icon-192.png manifest.webmanifest; do
  [ "$(code /$f)" = 200 ] && r=ok || r=no; check "200 /$f" $r
done
case "$(ctype /js/app.js)" in *javascript*) r=ok ;; *) r=no ;; esac; check "MIME javascript untuk modul" $r
[ "$(code /tidak-ada.js)" = 404 ] && r=ok || r=no; check "404 untuk file yang tidak ada" $r
for p in /../BACA-SAYA.txt /..%2fBACA-SAYA.txt /..%5cBACA-SAYA.txt /%2e%2e/BACA-SAYA.txt /..%5cserver.ps1; do
  c=$(code "$p"); [ "$c" != 200 ] && r=ok || r=no; check "tolak path traversal $p ($c)" $r
done
exit $fail
