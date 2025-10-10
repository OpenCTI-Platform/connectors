# PowerShell equivalent of generate_connectors_manifests.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

Write-Host "In order to run, this script needs to install the following Python package: mistune."
Write-Host "Please double-check that you are in a virtual environment, or it will install this dependency globally."
$answer = Read-Host "Do you want to continue? (y/n)"

if ($answer.ToLower() -notmatch '^y') {
    Write-Host "OK, then see you :)"
    exit 0
}

# Install mistune
pip install mistune

# Find the generate_connectors_manifests.py file
$generate_manifests = Get-ChildItem -Path . -Recurse -Filter "generate_connectors_manifests.py" | Select-Object -First 1

if (-not $generate_manifests) {
    Write-Error "generate_connectors_manifests.py not found in the current directory tree."
    exit 1
}

Write-Host "`nGenerating connectors' manifests files..."
python $generate_manifests.FullName

Write-Host "`nThe script has run successfully. Please check that no connectors have been skipped due to errors."
Write-Host "You can now safely uninstall the following Python package: mistune."
