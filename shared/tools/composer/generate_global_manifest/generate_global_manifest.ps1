# PowerShell equivalent of generate_global_manifest.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

# Find generate_global_manifest.py
$generate_manifest = Get-ChildItem -Path . -Recurse -Filter "generate_global_manifest.py" | Select-Object -First 1

Write-Host "`nGenerating manifest file..."
python "$($generate_manifest.FullName)"

# Ensure manifest is created
$manifest_exists = Get-ChildItem -Path (Get-Location) -Recurse -Filter "manifest.json" | Select-Object -First 1

if ($manifest_exists -and (Test-Path $manifest_exists.FullName)) {
    Write-Host "✅- Manifest well created !" -ForegroundColor Green
} else {
    Write-Host "❌- Manifest not created !" -ForegroundColor Red
}
