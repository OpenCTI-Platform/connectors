import argparse
import os
import traceback
from pathlib import Path

from connector_migrator import ConnectorMigrator

ROOT_PATH = Path(__file__).parent.parent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script that migrate one connector")
    parser.add_argument("--connector-path", required=True, type=str)
    args = parser.parse_args()

    connector_directory_path = ROOT_PATH / args.connector_path
    if not os.path.exists(connector_directory_path):
        raise RuntimeError(
            f"Connector path '{connector_directory_path}' does not exist"
        )

    connector_config_schema_path = (
        connector_directory_path / "__metadata__" / "connector_config_schema.json"
    )
    # skip connectors that already have generated config JSON schema
    if os.path.exists(connector_config_schema_path):
        print(f"👌 Connector '{connector_directory_path}' already manager supported")

        exit(0)

    connector_migrator = ConnectorMigrator(connector_directory_path)

    try:
        print(f"⌛ Migration of '{connector_directory_path}' starting")

        print("  > Adapting template files...")
        connector_migrator.migrate_files()
        print("  > Files from template added ✓")

        print("  > Asking AI for custom fixes...")
        connector_migrator.apply_ai_fixes()
        print("  > AI fixes applied ✓")

        print("  > Cleaning directory...")
        connector_migrator.cleanup_directory()
        print("  > Connector cleaned ✓")

        print(f"✅ Migration of '{connector_directory_path}' done")

        try:
            print("  > Formatting files...")
            connector_migrator.format_files()
            print("  > Files formatted ✓")
        except RuntimeError as e:
            print(
                f"❗An error occured during formatting. It should not affect the tests though."
            )

        exit(0)
    except Exception as e:
        print(
            f"❌ Skipping migration of '{connector_directory_path}' due to the following exception: {e}"
        )
        traceback.print_exc()

        connector_migrator.restore()

        exit(1)
