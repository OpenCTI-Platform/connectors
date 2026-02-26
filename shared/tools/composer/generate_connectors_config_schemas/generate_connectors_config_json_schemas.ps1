# PowerShell equivalent of generate_connectors_config_json_schemas.sh

# Set error action preference to stop on error
$ErrorActionPreference = "Stop"

$CONNECTOR_METADATA_DIRECTORY = "__metadata__"
$VENV_NAME = ".temp_venv"

function Find-RequirementsTxt {
    param(
        [string]$Path
    )
    
    # Find all requirements.txt files recursively
    # Sort by path depth (number of backslashes) and take the first one (shortest path)
    $file = Get-ChildItem -Path $Path -Filter "requirements.txt" -Recurse |
        Select-Object @{Name='Depth';Expression={($_.FullName -split '\\').Count}}, FullName |
        Sort-Object Depth |
        Select-Object -First 1
    
    if ($file) {
        return $file.FullName
    }
    return $null
}

function Find-PyprojectToml {
    param(
        [string]$Path
    )
    
    # Find all pyproject.toml files recursively
    # Sort by path depth (number of backslashes) and take the first one (shortest path)
    $file = Get-ChildItem -Path $Path -Filter "pyproject.toml" -Recurse |
        Select-Object @{Name='Depth';Expression={($_.FullName -split '\\').Count}}, FullName |
        Sort-Object Depth |
        Select-Object -First 1
    
    if ($file) {
        return $file.FullName
    }
    return $null
}

function Activate-Venv {
    param(
        [string]$ConnectorPath
    )
    
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
    
    # Install dependencies from connector's directory
    Push-Location -Path $ConnectorPath
    Write-Host "> Installing dependencies in: $ConnectorPath"
    
    $requirementsFile = Find-RequirementsTxt -Path $ConnectorPath
    if ($requirementsFile) {
        # Install requirements quietly
        & python -m pip install -q -r $requirementsFile
    } else {
        # If no requirements.txt, try to install the connector as a package (assuming pyproject.toml exists)
        & python -m pip install .
    }

    # Return to original working directory
    Pop-Location
    
    # Check if venv is well created
    if (Test-Path $venvPath) {
        Write-Host "✅ Dependencies installed for: $ConnectorPath" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Dependencies not installed for: $ConnectorPath" -ForegroundColor Red
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

# Find all parent directories of connectors with metadata directory
$connector_directories = Get-ChildItem -Path . -Directory -Recurse -Filter $CONNECTOR_METADATA_DIRECTORY |
    Select-Object -ExpandProperty Parent |
    Select-Object -Unique

# Check if we're running in a CI environment
$CIRCLE_BRANCH = $env:CIRCLE_BRANCH
if (-not $CIRCLE_BRANCH) {
    Write-Host "Note: Not running in CI environment. Will process all connectors with changes." -ForegroundColor Yellow
}

foreach ($connector_directory in $connector_directories) {
    $connector_path = $connector_directory.FullName
    
    if (Test-Path $connector_path) {
        # Check if directory has changed (simplified for local development)
        $hasChanges = $true  # Default to true for local development
        if ($CIRCLE_BRANCH) {
            # CI environment logic
            if ($CIRCLE_BRANCH -eq "release/6.9.x") {
                $gitDiff = & git diff HEAD~1 HEAD -- $connector_path
            } else {
                $mergeBase = & git merge-base release/6.9.x HEAD
                $gitDiff = & git diff $mergeBase HEAD $connector_path
            }
            $hasChanges = -not [string]::IsNullOrEmpty($gitDiff)
        }
        
        # Check if connector is supported
        $manifestPath = Join-Path $connector_path "$CONNECTOR_METADATA_DIRECTORY\connector_manifest.json"
        $isNotSupported = $false
        if (Test-Path $manifestPath) {
            $manifestContent = Get-Content $manifestPath -Raw
            if ($manifestContent -match '"manager_supported":\s*false') {
                $isNotSupported = $true
            }
        }
        
        if (-not $hasChanges) {
            Write-Host "Nothing has changed in: $connector_path"
        } elseif ($isNotSupported) {
            Write-Host "Connector is not supported: $connector_path"
        } else {
            Write-Host "Changes in: $connector_path"
            Write-Host "> Looking for a config model in $connector_path"

            $requirementsFile = Find-RequirementsTxt -Path $connector_path
            $pyprojectToml = Find-PyprojectToml -Path $connector_path

            if ($requirementsFile) {
                $requirementsContent = Get-Content $requirementsFile -Raw
                if ($requirementsContent -match "pydantic-settings" -or $requirementsContent -match "connectors-sdk") {
                    Write-Host "Found requirements.txt: $requirementsFile"
                }
            } elseif ($pyprojectToml) {
                $pyprojectTomlContent = Get-Content $pyprojectToml -Raw
                if ($pyprojectTomlContent -match "connectors-sdk") {
                    Write-Host "Found pyproject.toml: $pyprojectToml"
                }
            } else {
                Write-Host "Warning: pydantic-settings or connectors-sdk not found in connector's dependencies" -ForegroundColor Yellow
                Write-Host "This connector may not support config schema generation." -ForegroundColor Yellow
                continue
            }
            
            # Create a new PowerShell session to isolate the virtual environment
            $scriptBlock = {
                param($ConnectorPath, $VENV_NAME)
                
                if (Activate-Venv -ConnectorPath $ConnectorPath) {
                    # Generate connector JSON schema
                    $generator = Get-ChildItem -Path . -Recurse -Filter "generate_connector_config_json_schema.py.sample" | 
                        Select-Object -First 1
                    
                    if ($generator) {
                        $tempScript = Join-Path $ConnectorPath "generate_connector_config_json_schema_tmp.py"
                        Copy-Item -Path $generator.FullName -Destination $tempScript
                        & python $tempScript
                        Remove-Item $tempScript -Force
                    }
                    
                    # Generate configurations table
                    & python -m pip install -q --disable-pip-version-check jsonschema_markdown
                    
                    $configGenerator = Get-ChildItem -Path . -Recurse -Filter "generate_connector_config_doc.py.sample" | 
                        Select-Object -First 1
                    
                    if ($configGenerator) {
                        $tempConfigScript = Join-Path $ConnectorPath "generate_connector_config_doc_tmp.py"
                        Copy-Item -Path $configGenerator.FullName -Destination $tempConfigScript
                        & python $tempConfigScript
                        Remove-Item $tempConfigScript -Force
                    }
                    
                    # Clean up
                    Deactivate-Venv -VenvPath (Join-Path $ConnectorPath $VENV_NAME)
                }
            }
            
            # Execute in isolated session
            Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $connector_path, $VENV_NAME
        }
    }
}

Write-Host "`nDone processing all connectors." -ForegroundColor Green
