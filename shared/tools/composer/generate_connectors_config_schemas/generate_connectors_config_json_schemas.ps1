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
            if ($CIRCLE_BRANCH -eq "master") {
                $gitDiff = & git diff HEAD~1 HEAD -- $connector_path
            } else {
                $mergeBase = & git merge-base master HEAD
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
            Write-Host "> Looking for a config loader in $connector_path"
            
            $requirements_file = Find-RequirementsTxt -Path $connector_path
            if ($requirements_file) {
                Write-Host "Found requirements.txt: $requirements_file"
                
                # Check if requirements file contains pydantic-settings
                $requirementsContent = Get-Content $requirements_file -Raw
                if ($requirementsContent -match "pydantic-settings") {
                    # Create a new PowerShell session to isolate the virtual environment
                    $scriptBlock = {
                        param($ConnectorPath, $VENV_NAME)
                        
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
                            if (Get-Command deactivate -ErrorAction SilentlyContinue) {
                                deactivate
                            }
                            $venvPath = Join-Path $ConnectorPath $VENV_NAME
                            if (Test-Path $venvPath) {
                                Remove-Item -Path $venvPath -Recurse -Force
                            }
                        }
                    }
                    
                    # Execute in isolated session
                    Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $connector_path, $VENV_NAME
                }
            }
        }
    }
}

Write-Host "`nDone processing all connectors." -ForegroundColor Green
