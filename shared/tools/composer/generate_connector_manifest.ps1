# PowerShell equivalent of generate_connector_manifest.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

function Find-ConnectorDirectory {
    param(
        [string]$ConnectorName
    )
    
    # Find all directories with given name recursively
    # Sort by path depth (number of backslashes) and take the first one
    $directories = Get-ChildItem -Path . -Directory -Recurse | 
        Where-Object { $_.Name -like "*$ConnectorName*" } |
        Select-Object @{Name='Depth';Expression={($_.FullName -split '\\').Count}}, FullName |
        Sort-Object Depth |
        Select-Object -First 1
    
    if ($directories) {
        return $directories.FullName
    }
    return $null
}

$CONNECTOR_METADATA_DIRECTORY = "__metadata__"

Write-Host "Adding metadata info for a connector..."

$CONNECTOR_NAME = Read-Host "In which existing connector?(give connector folder name)"

$CONNECTOR_DIRECTORY = Find-ConnectorDirectory -ConnectorName $CONNECTOR_NAME

if ($CONNECTOR_DIRECTORY) {
    Write-Host "Found this directory : $CONNECTOR_DIRECTORY"
    
    $ANSWER = Read-Host "Is it the correct connector?(y/n)"
    
    if ($ANSWER -match '^[yY]') {
        Write-Host "Adding info file for: $CONNECTOR_NAME"
        
        # Create metadata directory if it doesn't exist
        $metadataPath = Join-Path $CONNECTOR_DIRECTORY $CONNECTOR_METADATA_DIRECTORY
        if (-not (Test-Path $metadataPath)) {
            New-Item -ItemType Directory -Path $metadataPath -Force | Out-Null
        }
        
        # Copy connector manifest template
        $metadata_sample = Get-ChildItem -Path . -Recurse -Filter "connector_manifest.json.sample" | Select-Object -First 1
        if ($metadata_sample) {
            $destinationPath = Join-Path $metadataPath "connector_manifest.json"
            Copy-Item -Path $metadata_sample.FullName -Destination $destinationPath -Force
            Write-Host "You can complete metadata for the connector."
        } else {
            Write-Host "Error: Could not find connector_manifest.json.sample" -ForegroundColor Red
        }
    } else {
        Write-Host "OK, then see you :)"
    }
} else {
    Write-Host "Could not find directory for connector: $CONNECTOR_NAME" -ForegroundColor Red
}
