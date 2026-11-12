#!/bin/sh
# Seekure offline - server lokal untuk macOS / Linux.
# Pakai: buka Terminal di folder ini lalu jalankan:  sh jalankan-seekure.sh
PORT=8737
URL="http://localhost:$PORT/"
cd "$(dirname "$0")/app" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
  echo "Seekure butuh python3. macOS: jalankan 'xcode-select --install'. Linux: pasang paket python3."
  exit 1
fi

if [ -z "$SEEKURE_NO_BROWSER" ]; then
  (
    sleep 1
    if command -v open >/dev/null 2>&1; then open "$URL"
    elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
    fi
  ) >/dev/null 2>&1 &
fi

echo ""
echo "  Seekure berjalan di $URL"
echo "  Biarkan Terminal ini terbuka selama memakai Seekure. Ctrl+C untuk berhenti."
echo ""
exec python3 -m http.server "$PORT" --bind 127.0.0.1
