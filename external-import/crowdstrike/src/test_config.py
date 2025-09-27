"""Test script to verify the new configuration system is working correctly"""

import json
import sys
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from models.configs.config_loader import ConfigLoader
    
    print("=" * 60)
    print("Testing CrowdStrike Configuration Loading")
    print("=" * 60)
    
    # Try to load configuration
    try:
        config = ConfigLoader()
        print("✓ Configuration loaded successfully!")
        print()
        
        # Display loaded configuration (excluding sensitive data)
        print("Configuration Summary:")
        print("-" * 40)
        
        # OpenCTI settings
        print(f"OpenCTI URL: {config.opencti.url if hasattr(config.opencti, 'url') else 'Not configured'}")
        print(f"OpenCTI Token: {'***' if hasattr(config.opencti, 'token') else 'Not configured'}")
        print()
        
        # Connector settings  
        print(f"Connector ID: {config.connector.id}")
        print(f"Connector Name: {config.connector.name}")
        print(f"Connector Type: {config.connector.type}")
        print(f"Log Level: {config.connector.log_level}")
        print(f"Scope: {config.connector.scope}")
        print(f"Duration Period: {config.connector.duration_period}")
        print()
        
        # CrowdStrike settings
        print(f"CrowdStrike Base URL: {config.crowdstrike.base_url}")
        print(f"Client ID: {'***' if config.crowdstrike.client_id else 'Not configured'}")
        print(f"Client Secret: {'***' if config.crowdstrike.client_secret else 'Not configured'}")
        print(f"TLP: {config.crowdstrike.tlp}")
        print(f"Create Observables: {config.crowdstrike.create_observables}")
        print(f"Create Indicators: {config.crowdstrike.create_indicators}")
        print(f"Scopes: {config.crowdstrike.scopes}")
        print()
        
        # Report settings
        print(f"Report Start Timestamp: {config.crowdstrike.report_start_timestamp}")
        print(f"Report Status: {config.crowdstrike.report_status}")
        print(f"Report Include Types: {config.crowdstrike.report_include_types}")
        print(f"Report Type: {config.crowdstrike.report_type}")
        print(f"Report Guess Malware: {config.crowdstrike.report_guess_malware}")
        print()
        
        # Indicator settings
        print(f"Indicator Start Timestamp: {config.crowdstrike.indicator_start_timestamp}")
        print(f"Indicator Exclude Types: {config.crowdstrike.indicator_exclude_types}")
        print(f"Default X OpenCTI Score: {config.crowdstrike.default_x_opencti_score}")
        print(f"Indicator Low Score: {config.crowdstrike.indicator_low_score}")
        print(f"Indicator Medium Score: {config.crowdstrike.indicator_medium_score}")
        print(f"Indicator High Score: {config.crowdstrike.indicator_high_score}")
        print()
        
        print(f"Interval (seconds): {config.crowdstrike.interval_sec}")
        print(f"No File Trigger Import: {config.crowdstrike.no_file_trigger_import}")
        print()
        
        # Test backward compatibility with ConfigCrowdstrike class
        print("Testing backward compatibility with ConfigCrowdstrike:")
        print("-" * 40)
        from crowdstrike_feeds_services.utils.config_variables import ConfigCrowdstrike
        old_config = ConfigCrowdstrike()
        print(f"✓ ConfigCrowdstrike loaded successfully")
        print(f"  Duration Period: {old_config.duration_period}")
        print(f"  Base URL: {old_config.base_url}")
        print(f"  Scopes: {old_config.scopes}")
        print(f"  TLP: {old_config.tlp}")
        print()
        
        print("=" * 60)
        print("Configuration test completed successfully!")
        print("=" * 60)
        
    except FileNotFoundError:
        print("⚠ No configuration file found (config.yml or .env)")
        print("This is expected if you haven't created one yet.")
        print("Copy config.yml.sample to config.yml and update with your settings.")
        
    except Exception as e:
        print(f"✗ Error loading configuration: {e}")
        print()
        print("Stack trace:")
        import traceback
        traceback.print_exc()
        
except ImportError as e:
    print(f"✗ Import error: {e}")
    print()
    print("Make sure all required dependencies are installed:")
    print("  pip install pydantic pydantic-settings pyyaml")
    print("  pip install git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk")
    import traceback
    traceback.print_exc()
