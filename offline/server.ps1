# Seekure offline - server lokal kecil untuk Windows (PowerShell bawaan, tanpa instalasi).
# Hanya melayani file di folder "app" lewat http://localhost:8737/ dan hanya untuk komputer ini.
# Tutup jendela ini (atau tekan Ctrl+C) untuk menghentikan Seekure.

$ErrorActionPreference = 'Stop'
$port = 8737
$url = "http://localhost:$port/"
$sep = [System.IO.Path]::DirectorySeparatorChar
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'app')).TrimEnd('\', '/') + $sep

$types = @{
  '.html' = 'text/html; charset=utf-8'
  '.js' = 'text/javascript; charset=utf-8'
  '.css' = 'text/css; charset=utf-8'
  '.svg' = 'image/svg+xml'
  '.png' = 'image/png'
  '.json' = 'application/json'
  '.webmanifest' = 'application/manifest+json'
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
try {
  $listener.Start()
} catch {
  Write-Host "Port $port sudah dipakai. Mungkin Seekure sudah berjalan - membuka browser saja."
  if (-not $env:SEEKURE_NO_BROWSER) { Start-Process $url }
  exit 0
}

Write-Host ''
Write-Host "  Seekure berjalan di $url"
Write-Host '  Jangan tutup jendela ini selama memakai Seekure.'
Write-Host '  Tutup jendela ini (atau Ctrl+C) untuk berhenti.'
Write-Host ''
if (-not $env:SEEKURE_NO_BROWSER) { Start-Process $url }

try {
  while ($listener.IsListening) {
    $task = $listener.GetContextAsync()
    while (-not $task.AsyncWaitHandle.WaitOne(500)) { }  # memberi kesempatan Ctrl+C
    $ctx = $task.GetAwaiter().GetResult()
    $res = $ctx.Response
    try {
      $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath).TrimStart('/')
      if ($rel -eq '') { $rel = 'index.html' }
      $path = [System.IO.Path]::GetFullPath((Join-Path $root $rel))
      if (-not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $res.StatusCode = 404
      } else {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
        $res.ContentType = $(if ($types.ContainsKey($ext)) { $types[$ext] } else { 'application/octet-stream' })
        $res.Headers.Add('Cache-Control', 'no-cache')
        $res.Headers.Add('X-Content-Type-Options', 'nosniff')
        $res.ContentLength64 = $bytes.Length
        $res.OutputStream.Write($bytes, 0, $bytes.Length)
      }
    } catch {
      $res.StatusCode = 500
    } finally {
      $res.Close()
    }
  }
} finally {
  $listener.Stop()
}
