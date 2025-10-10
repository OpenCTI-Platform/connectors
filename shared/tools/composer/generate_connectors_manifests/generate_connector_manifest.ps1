# PowerShell equivalent of generate_connector_manifest.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

function Find-ConnectorDirectories {
    param(
        [string]$ConnectorName
    )
    
    # Clean the search term (remove leading/trailing slashes)
    $searchTerm = $ConnectorName.Trim('/', '\')
    
    # Find all directories that match the search term
    # This can match either the directory name OR the path
    $directories = @()
    
    # If the search term contains a slash, treat it as a path pattern
    if ($searchTerm -match '[/\\]') {
        # Convert forward slashes to backslashes for Windows
        $pathPattern = $searchTerm -replace '/', '\'
        
        # First try to find exact match
        $exactMatch = Get-ChildItem -Path . -Directory -Recurse | 
            Where-Object { $_.FullName -match "\\$pathPattern$" }
        
        if ($exactMatch) {
            $directories = @($exactMatch)
        } else {
            # If no exact match, find directories that end with the path pattern
            # But filter out subdirectories - only keep the top-level match
            $allMatches = Get-ChildItem -Path . -Directory -Recurse | 
                Where-Object { $_.FullName -like "*\$pathPattern" -or $_.FullName -like "*\$pathPattern\*" }
            
            # Keep only the shortest matching paths (root directories)
            $rootDirs = @()
            foreach ($dir in $allMatches) {
                $isRoot = $true
                foreach ($otherDir in $allMatches) {
                    if ($dir.FullName -ne $otherDir.FullName -and $dir.FullName.StartsWith($otherDir.FullName + '\')) {
                        $isRoot = $false
                        break
                    }
                }
                if ($isRoot) {
                    $rootDirs += $dir
                }
            }
            $directories = $rootDirs
        }
    } else {
        # Otherwise, just match on the directory name (but only connector roots)
        $allMatches = Get-ChildItem -Path . -Directory -Recurse | 
            Where-Object { $_.Name -like "*$searchTerm*" }
        
        # Filter to only include directories that have common connector indicators
        $directories = $allMatches | Where-Object {
            # Check if it's likely a connector root (has src, requirements.txt, or __metadata__)
            $hasRequirements = Test-Path (Join-Path $_.FullName "requirements.txt")
            $hasSrc = Test-Path (Join-Path $_.FullName "src")
            $hasMetadata = Test-Path (Join-Path $_.FullName "__metadata__")
            return $hasRequirements -or $hasSrc -or $hasMetadata
        }
    }
    
    # Sort by path depth (prefer shallower directories)
    $sortedDirs = $directories |
        Select-Object @{Name='Depth';Expression={($_.FullName -split '\\').Count}}, FullName |
        Sort-Object Depth
    
    return $sortedDirs
}

$CONNECTOR_METADATA_DIRECTORY = "__metadata__"

Write-Host "Adding metadata info for a connector..."

$CONNECTOR_NAME = Read-Host "In which existing connector? (give connector folder name)"

# Find matching connector directories
$matchingDirectories = Find-ConnectorDirectories -ConnectorName $CONNECTOR_NAME

if ($matchingDirectories.Count -eq 0) {
    Write-Host "Could not find any directory matching: $CONNECTOR_NAME" -ForegroundColor Red
    exit 1
}

# Select the connector directory
$CONNECTOR_DIRECTORY = $null

if ($matchingDirectories.Count -eq 1) {
    # Only one match found
    $CONNECTOR_DIRECTORY = $matchingDirectories[0].FullName
    Write-Host "Found this directory: $CONNECTOR_DIRECTORY" -ForegroundColor Yellow
    
    # Ask for confirmation
    $ANSWER = Read-Host "Is this the correct connector? (y/n)"
    
    if ($ANSWER -notmatch '^[yY]') {
        Write-Host "OK, then see you :)" -ForegroundColor Yellow
        exit 0
    }
} else {
    # Multiple matches found
    Write-Host "Found multiple connectors matching '$CONNECTOR_NAME':" -ForegroundColor Yellow
    Write-Host ""
    
    for ($i = 0; $i -lt $matchingDirectories.Count; $i++) {
        $relPath = $matchingDirectories[$i].FullName.Replace("$PWD\", "").Replace("$PWD/", "")
        Write-Host "  [$($i+1)] $relPath"
    }
    Write-Host "  [0] Cancel"
    Write-Host ""
    
    $selection = Read-Host "Please select the connector you want to process (enter number)"
    
    if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "OK, then see you :)" -ForegroundColor Yellow
        exit 0
    }
    
    try {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $matchingDirectories.Count) {
            $CONNECTOR_DIRECTORY = $matchingDirectories[$index].FullName
            Write-Host ""
            Write-Host "Selected: $CONNECTOR_DIRECTORY" -ForegroundColor Green
        } else {
            Write-Host "Invalid selection." -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "Invalid selection." -ForegroundColor Red
        exit 1
    }
}

if ($CONNECTOR_DIRECTORY) {
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
}
