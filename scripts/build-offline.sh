#!/bin/sh
# Membangun paket Seekure offline (zip) secara reproducible.
# Hasil: dist/seekure-offline-vX.Y.Z.zip, dist/SHA256SUMS.txt, dist/RELEASE_NOTES.md
set -eu
cd "$(dirname "$0")/.."

V=$(sed -n "s/.*APP_VERSION = '\([^']*\)'.*/\1/p" js/version.js)
[ -n "$V" ] || { echo "APP_VERSION tidak ditemukan di js/version.js" >&2; exit 1; }
NAME="seekure-offline-v$V"
OUT=dist
STAGE="$OUT/$NAME"
EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
COMMIT=$(git rev-parse HEAD)

rm -rf "$OUT"
mkdir -p "$STAGE/app"
cp -R index.html manifest.webmanifest sw.js css js vendor icons "$STAGE/app/"
cp offline/server.ps1 offline/Jalankan-Seekure-Windows.cmd offline/BACA-SAYA.txt offline/jalankan-seekure.sh "$STAGE/"

# File untuk Windows memakai akhir baris CRLF; sisanya LF.
for f in server.ps1 Jalankan-Seekure-Windows.cmd BACA-SAYA.txt; do
  sed 's/\r*$/\r/' "$STAGE/$f" > "$STAGE/$f.tmp" && mv "$STAGE/$f.tmp" "$STAGE/$f"
done

# Normalisasi izin & waktu agar zip identik di mesin mana pun.
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/jalankan-seekure.sh"
find "$STAGE" -exec touch -h -d "@$EPOCH" {} +

(cd "$OUT" && find "$NAME" -type f | LC_ALL=C sort | TZ=UTC zip -X -D -q "$NAME.zip" -@)
(cd "$OUT" && sha256sum "$NAME.zip" > SHA256SUMS.txt)
HASH=$(cut -d' ' -f1 "$OUT/SHA256SUMS.txt")

cat > "$OUT/RELEASE_NOTES.md" <<NOTES
## Seekure v$V

**Versi offline** (\`$NAME.zip\`) berjalan dari komputer Anda dan **tidak pernah update otomatis**.
Cara pakai ada di \`BACA-SAYA.txt\` di dalam zip.

| | |
|---|---|
| SHA-256 | \`$HASH\` |
| Commit | \`$COMMIT\` |

Periksa hash sebelum menjalankan:

- Windows: \`certutil -hashfile $NAME.zip SHA256\`
- macOS: \`shasum -a 256 $NAME.zip\`
- Linux: \`sha256sum $NAME.zip\`

Paket ini *reproducible*: checkout tag \`v$V\`, jalankan \`sh scripts/build-offline.sh\`, lalu hash zip yang dihasilkan harus sama persis dengan di atas.

Versi online selalu tersedia di https://woeatomo.github.io/Seekure/
NOTES

echo "$HASH  $OUT/$NAME.zip"
