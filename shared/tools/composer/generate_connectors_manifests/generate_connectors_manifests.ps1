# PowerShell equivalent of generate_connectors_manifests.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

# Find the generate_connectors_manifests.py file
$generate_manifests = Get-ChildItem -Path . -Recurse -Filter "generate_connectors_manifests.py" | Select-Object -First 1

if (-not $generate_manifests) {
    Write-Error "generate_connectors_manifests.py not found in the current directory tree."
    exit 1
}

Write-Host "`nGenerating connectors' manifests files..."
python $generate_manifests.FullName
