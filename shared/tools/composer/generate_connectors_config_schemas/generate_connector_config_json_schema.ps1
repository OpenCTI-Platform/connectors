# PowerShell script to generate config JSON schema for a single targeted connector
# This is the singular version of generate_connectors_config_json_schemas.ps1

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

$CONNECTOR_METADATA_DIRECTORY = "__metadata__"
$VENV_NAME = ".temp_venv"

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
    $sortedDirs = $directories | Sort-Object { ($_.FullName -split '\\').Count }
    
    return $sortedDirs
}

function Find-RequirementsTxt {
    param(
        [string]$Path
    )
    
    # Find all requirements.txt files recursively
    # Sort by path depth (number of backslashes) and take the first one (shortest path)
    $files = Get-ChildItem -Path $Path -Filter "requirements.txt" -Recurse |
        Select-Object @{Name='Depth';Expression={($_.FullName -split '\\').Count}}, FullName |
        Sort-Object Depth |
        Select-Object -First 1
    
    if ($files) {
        return $files.FullName
    }
    return $null
}

function Activate-Venv {
    param(
        [string]$ConnectorPath
    )
    
    $requirements_file = Find-RequirementsTxt -Path $ConnectorPath
    
    if (-not $requirements_file) {
        Write-Host "No requirements.txt found in $ConnectorPath" -ForegroundColor Yellow
        return $false
    }
    
    # Create isolated virtual environment in connector path
    $venvPath = Join-Path $ConnectorPath $VENV_NAME
    & python -m venv $venvPath
    
    # Activate virtual environment (Windows)
    $activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
    if (Test-Path $activateScript) {
        & $activateScript
    } else {
        Write-Host "Could not find activation script at $activateScript" -ForegroundColor Red
        return $false
    }
    
    Write-Host "> Installing requirements in: $ConnectorPath"
    
    # Install requirements quietly
    & python -m pip install -q -r $requirements_file
    
    # Check if venv is well created
    if (Test-Path $venvPath) {
        Write-Host "✅ Requirements installed for: $ConnectorPath" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Requirements not installed for: $ConnectorPath" -ForegroundColor Red
        return $false
    }
}

function Deactivate-Venv {
    param(
        [string]$VenvPath
    )
    
    Write-Host "> Cleaning up environment..."
    
    # Deactivate virtual environment
    if (Get-Command deactivate -ErrorAction SilentlyContinue) {
        deactivate
    }
    
    # Remove virtual environment folder
    if (Test-Path $VenvPath) {
        Remove-Item -Path $VenvPath -Recurse -Force
    }
}

# Main script
Write-Host "Generating config JSON schemas for a single connector..." -ForegroundColor Cyan
Write-Host ""

# Ask for connector name
$CONNECTOR_NAME = Read-Host "Which connector do you want to generate schemas for? (give connector folder name)"

# Find matching connector directories
$matchingDirectories = @(Find-ConnectorDirectories -ConnectorName $CONNECTOR_NAME)

if ($matchingDirectories.Count -eq 0) {
    Write-Host "No connector found matching: '$CONNECTOR_NAME'" -ForegroundColor Red
    Write-Host "Please check the connector name and try again." -ForegroundColor Yellow
    exit 1
}

# Select the connector directory
$CONNECTOR_DIRECTORY = $null

if ($matchingDirectories.Count -eq 1) {
    # Only one match found
    $CONNECTOR_DIRECTORY = $matchingDirectories[0].FullName
    $relPath = $CONNECTOR_DIRECTORY.Replace("$PWD\", "").Replace("$PWD/", "")
    Write-Host "Found this directory: $relPath" -ForegroundColor Yellow
    
    # Ask for confirmation
    $ANSWER = Read-Host "Is this the correct connector? (y/n)"
    
    if ($ANSWER -notmatch '^[yY]') {
        Write-Host "Aborted by user." -ForegroundColor Yellow
        exit 0
    }
} else {
    # Multiple matches found
    Write-Host "Found multiple connectors matching '$CONNECTOR_NAME':" -ForegroundColor Yellow
    Write-Host ""
    
    for ($i = 0; $i -lt $matchingDirectories.Count; $i++) {
        $fullPath = $matchingDirectories[$i].FullName
        $relPath = $fullPath.Replace("$PWD\", "").Replace("$PWD/", "")
        Write-Host "  [$($i+1)] $relPath"
    }
    Write-Host "  [0] Cancel"
    Write-Host ""
    
    $selection = Read-Host "Please select the connector you want to process (enter number)"
    
    if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "Aborted by user." -ForegroundColor Yellow
        exit 0
    }
    
    try {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $matchingDirectories.Count) {
            $CONNECTOR_DIRECTORY = $matchingDirectories[$index].FullName
            $relPath = $CONNECTOR_DIRECTORY.Replace("$PWD\", "").Replace("$PWD/", "")
            Write-Host ""
            Write-Host "Selected: $relPath" -ForegroundColor Green
        } else {
            Write-Host "Invalid selection." -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "Invalid selection." -ForegroundColor Red
        exit 1
    }
}

# Check if metadata directory exists
$metadataPath = Join-Path $CONNECTOR_DIRECTORY $CONNECTOR_METADATA_DIRECTORY
if (-not (Test-Path $metadataPath)) {
    Write-Host "Warning: No $CONNECTOR_METADATA_DIRECTORY directory found in $CONNECTOR_DIRECTORY" -ForegroundColor Yellow
    Write-Host "Creating metadata directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $metadataPath -Force | Out-Null
}

# Check if connector is supported
$manifestPath = Join-Path $metadataPath "connector_manifest.json"
$isNotSupported = $false
if (Test-Path $manifestPath) {
    $manifestContent = Get-Content $manifestPath -Raw
    if ($manifestContent -match '"manager_supported":\s*false') {
        $isNotSupported = $true
        Write-Host "Warning: Connector is marked as not supported in manifest." -ForegroundColor Yellow
        $continueAnswer = Read-Host "Do you want to continue anyway? (y/n)"
        if ($continueAnswer -notmatch '^[yY]') {
            Write-Host "Aborted by user." -ForegroundColor Yellow
            exit 0
        }
    }
}

Write-Host ""
Write-Host "Processing connector: $CONNECTOR_NAME" -ForegroundColor Green
Write-Host "> Looking for a config loader in $CONNECTOR_DIRECTORY"

$requirements_file = Find-RequirementsTxt -Path $CONNECTOR_DIRECTORY
if ($requirements_file) {
    Write-Host "Found requirements.txt: $requirements_file"
    
    # Check if requirements file contains pydantic-settings
    $requirementsContent = Get-Content $requirements_file -Raw
    if ($requirementsContent -match "pydantic-settings") {
        Write-Host "Found pydantic-settings in requirements. Proceeding with schema generation..." -ForegroundColor Green
        
        # Create a new PowerShell session to isolate the virtual environment
        $scriptBlock = {
            param($ConnectorPath, $VENV_NAME)
            
            # Save the original directory
            $originalDir = Get-Location
            
            # Change to the connector directory for all operations
            Set-Location -Path $ConnectorPath
            
            # Recreate functions in the new session
            function Activate-Venv {
                param([string]$ConnectorPath)
                
                # Find requirements.txt
                $requirements = Get-ChildItem -Path $ConnectorPath -Filter "requirements.txt" -Recurse | 
                    Select-Object -First 1
                
                if ($requirements) {
                    $venvPath = Join-Path $ConnectorPath $VENV_NAME
                    & python -m venv $venvPath
                    
                    $activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
                    if (Test-Path $activateScript) {
                        & $activateScript
                        & python -m pip install -q -r $requirements.FullName
                        return $true
                    }
                }
                return $false
            }
            
            if (Activate-Venv -ConnectorPath $ConnectorPath) {
                Write-Host "> Generating connector JSON schema..." -ForegroundColor Cyan
                
                # Generate connector JSON schema
                # Find the generator script from the original location
                $generator = Get-ChildItem -Path $originalDir -Recurse -Filter "generate_connector_config_json_schema.py.sample" | 
                    Select-Object -First 1
                
                if ($generator) {
                    $tempScript = "generate_connector_config_json_schema_tmp.py"
                    Copy-Item -Path $generator.FullName -Destination $tempScript
                    & python $tempScript
                    Remove-Item $tempScript -Force
                    Write-Host "✅ JSON schema generated successfully" -ForegroundColor Green
                } else {
                    Write-Host "❌ Could not find generate_connector_config_json_schema.py.sample" -ForegroundColor Red
                }
                
                Write-Host "> Generating configurations table..." -ForegroundColor Cyan
                
                # Generate configurations table
                & python -m pip install -q --disable-pip-version-check jsonschema_markdown
                
                $configGenerator = Get-ChildItem -Path $originalDir -Recurse -Filter "generate_connector_config_doc.py.sample" | 
                    Select-Object -First 1
                
                if ($configGenerator) {
                    $tempConfigScript = "generate_connector_config_doc_tmp.py"
                    Copy-Item -Path $configGenerator.FullName -Destination $tempConfigScript
                    & python $tempConfigScript
                    Remove-Item $tempConfigScript -Force
                    Write-Host "✅ Configuration documentation generated successfully" -ForegroundColor Green
                } else {
                    Write-Host "❌ Could not find generate_connector_config_doc.py.sample" -ForegroundColor Red
                }
                
                # Clean up
                if (Get-Command deactivate -ErrorAction SilentlyContinue) {
                    deactivate
                }
                $venvPath = Join-Path $ConnectorPath $VENV_NAME
                if (Test-Path $venvPath) {
                    Remove-Item -Path $venvPath -Recurse -Force
                }
            } else {
                Write-Host "❌ Failed to activate virtual environment" -ForegroundColor Red
            }
        }
        
        # Execute in isolated session
        Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $CONNECTOR_DIRECTORY, $VENV_NAME
        
        Write-Host ""
        Write-Host "✅ Schema generation completed for connector: $CONNECTOR_NAME" -ForegroundColor Green
    } else {
        Write-Host "Warning: pydantic-settings not found in requirements.txt" -ForegroundColor Yellow
        Write-Host "This connector may not support config schema generation." -ForegroundColor Yellow
    }
} else {
    Write-Host "Error: No requirements.txt found in connector directory." -ForegroundColor Red
    Write-Host "Cannot proceed with schema generation." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
